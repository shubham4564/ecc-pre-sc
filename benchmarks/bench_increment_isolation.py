"""
bench_increment_isolation.py
----------------------------
Measures the gas cost attributable exclusively to the counting logic
(Counter.increment()) by deploying two PRE contract instances that are
identical except for the `countingEnabled` flag, then computing the
per-call gas delta.

Usage:
    python benchmarks/bench_increment_isolation.py [--iters N]

Environment (.env):
    RPC_URL        - Ethereum RPC endpoint (e.g. Sepolia via Alchemy)
    PRIVATE_KEY    - Deployer/SP wallet private key
    CHAIN_ID       - (optional) defaults to 11155111 (Sepolia)

Outputs:
    benchmarks/increment_isolation_bench.csv
        columns: iteration, gas_with_counting, gas_without_counting, delta_gas
"""

import os
import sys
import csv
import time
import json
import secrets
import pathlib
import argparse
import statistics

from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
DATA_DIR = ROOT / "data"
OUT_CSV = pathlib.Path(__file__).parent / "increment_isolation_bench.csv"
GAS_REPORT_FILE = DATA_DIR / "gas_report.json"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import SP as sp_module
from gas_utils import GasReportStore, format_tx_gas_summary, print_tx_gas_summary

# ---------------------------------------------------------------------------
# Contract loading helpers
# ---------------------------------------------------------------------------

def load_pre_artifact():
    """Load PRE ABI and bytecode from the compiled JSON produced by CODeployment."""
    artifact_path = DATA_DIR / "PRE_compData1.json"
    with open(artifact_path, "r") as f:
        data = json.load(f)
    pre = data.get("PRE")
    if not pre or "abi" not in pre or "bytecode" not in pre:
        raise RuntimeError(f"Cannot find PRE artifact in {artifact_path}")
    bytecode = pre["bytecode"]
    if isinstance(bytecode, dict):
        bytecode = bytecode.get("object", "")
    return pre["abi"], bytecode


def load_counter_abi():
    counter_path = DATA_DIR / "Counter_compData.json"
    with open(counter_path, "r") as f:
        data = json.load(f)
    # Support both wrapped {"Counter": {"abi": ...}} and flat {"abi": ...} formats
    if "abi" in data:
        return data["abi"]
    counter = data.get("Counter")
    if counter and "abi" in counter:
        return counter["abi"]
    raise RuntimeError(f"Cannot find Counter ABI in {counter_path}")




# ---------------------------------------------------------------------------
# Deployment
# ---------------------------------------------------------------------------

def make_ciphertext_args():
    """
    Generate one fresh CO ciphertext and return the constructor args list
    (everything except `counting_enabled` and wallet fields, which are added
    by `deploy_pre`).  Reusing the same ciphertext for both contract deployments
    guarantees that the Solidity `hash = keccak(c1,c2,c3,c4) % PP` is
    identical, so the `hash * c2` FastEcMul operation costs exactly the same
    gas in both the with-counting and without-counting contracts — leaving the
    measured delta as the pure overhead of `Counter.increment()`.
    """
    from CODeployment import CO
    from eth_hash.auto import keccak as keccak_fn

    PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    co = CO()
    k_i = os.urandom(16)
    co.key_generate(128)
    c1, c2, c3, c4, c5 = co.encrypt(k_i)

    # Derive c5TimesP from Solidity's abi.encodePacked hash (32-byte-padded
    # uint256 values) so the on-chain integrity check always passes even when
    # EC point x-coordinates have leading zero nibbles in their hex representation.
    c3_bytes = bytes.fromhex(c3)
    encoded = (
        int(c1.x()).to_bytes(32, 'big') +
        int(c2.x()).to_bytes(32, 'big') +
        c3_bytes +
        int(c4.x()).to_bytes(32, 'big')
    )
    h_sol = int.from_bytes(keccak_fn(encoded), 'big') % PP
    c5p_point = c4 + h_sol * c2
    c5_times_p_x = int(c5p_point.x())

    return [
        int(c1.x()), int(c1.y()),
        int(c2.x()), int(c2.y()),
        "0x" + c3,
        int(c4.x()), int(c4.y()),
        c5_times_p_x,
    ]


def deploy_pre(w3: Web3, acct: Account, pk: str, chain_id: int,
               abi, bytecode, sp_proof_material: dict,
               ciphertext_args: list,
               counting_enabled: bool) -> tuple:
    """
    Deploy one PRE instance using pre-computed `ciphertext_args`.
    Returns (pre_address, counter_address).
    """
    constructor_args = ciphertext_args + [
        acct.address,
        [acct.address],
        counting_enabled,
    ]

    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    block = w3.eth.get_block("latest")
    block_gas_limit = int(block["gasLimit"])

    construct_txn = Contract.constructor(*constructor_args).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
        "gas": min(7_000_000, block_gas_limit - 100_000),
        "maxFeePerGas": w3.to_wei("60", "gwei"),
        "maxPriorityFeePerGas": w3.to_wei("2", "gwei"),
        "chainId": chain_id,
    })

    signed = w3.eth.account.sign_transaction(construct_txn, private_key=pk)
    raw_tx = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction")
    tx_hash = w3.eth.send_raw_transaction(raw_tx)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt["status"] != 1:
        raise RuntimeError(f"PRE deployment failed (countingEnabled={counting_enabled})")

    pre_address = Web3.to_checksum_address(str(receipt.contractAddress))
    deployed_pre = w3.eth.contract(address=pre_address, abi=abi)
    counter_address = Web3.to_checksum_address(deployed_pre.functions.countingContract().call())

    # Register the SP proof public key in the Counter contract
    counter_abi = load_counter_abi()
    counter_contract = w3.eth.contract(address=counter_address, abi=counter_abi)
    set_key_txn = counter_contract.functions.setProofPublicKey(
        acct.address,
        int(sp_proof_material["public_key_x"]),
        int(sp_proof_material["public_key_y"]),
    ).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
        "gas": min(300_000, block_gas_limit - 100_000),
        "maxFeePerGas": w3.to_wei("60", "gwei"),
        "maxPriorityFeePerGas": w3.to_wei("2", "gwei"),
        "chainId": chain_id,
    })
    signed_key = w3.eth.account.sign_transaction(set_key_txn, private_key=pk)
    raw_key = getattr(signed_key, "rawTransaction", None) or getattr(signed_key, "raw_transaction")
    key_hash = w3.eth.send_raw_transaction(raw_key)
    key_receipt = w3.eth.wait_for_transaction_receipt(key_hash)
    if key_receipt["status"] != 1:
        raise RuntimeError(f"setProofPublicKey failed for countingEnabled={counting_enabled}")

    label = f"Deploy PRE (countingEnabled={counting_enabled})"
    print(f"[deploy] {label}: pre={pre_address}, counter={counter_address}")
    return pre_address, counter_address


# ---------------------------------------------------------------------------
# reEncrypt call helpers
# ---------------------------------------------------------------------------

def make_reencrypt_params(sp: sp_module.SP, contract_address: str,
                          sender_address: str,
                          rk1: int, rk2: int, rk3: int) -> dict:
    """
    Build a ReEncryptInputs struct for `contract_address`, reusing caller-
    supplied `rk1/rk2/rk3` so both the with- and without-counting calls in the
    same iteration operate on identical scalars for FastEcMul.
    """
    proof = sp.generate_reencryption_proof(contract_address, sender_address, rk1, rk2, rk3)
    return {
        "rk1": rk1,
        "rk2": rk2,
        "rk3": rk3,
        "commitment": proof["commitment"],
        "response":   proof["response"],
        "nonce":      proof["nonce"],
        "expiry":     proof["expiry"],
    }


def send_reencrypt(w3: Web3, contract, acct: Account, pk: str,
                   chain_id: int, params: dict) -> int:
    """Send one reEncrypt transaction and return gas_used."""
    # Dry-run via .call() to surface any revert reason before spending gas
    try:
        contract.functions.reEncrypt(params).call({"from": acct.address})
    except Exception as call_err:
        raise RuntimeError(f"reEncrypt call() reverted: {call_err}") from call_err

    block_gas_limit = int(w3.eth.get_block("latest")["gasLimit"])
    tx = contract.functions.reEncrypt(params).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
        "gas": min(5_000_000, block_gas_limit - 100_000),
        "maxFeePerGas": w3.to_wei("50", "gwei"),
        "maxPriorityFeePerGas": w3.to_wei("1", "gwei"),
        "chainId": chain_id,
    })
    signed = w3.eth.account.sign_transaction(tx, private_key=pk)
    raw_tx = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction")
    tx_hash = w3.eth.send_raw_transaction(raw_tx)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    if receipt["status"] != 1:
        raise RuntimeError(f"reEncrypt failed on-chain: {tx_hash.hex()}")
    return int(receipt["gasUsed"])


# ---------------------------------------------------------------------------
# Main benchmark
# ---------------------------------------------------------------------------

def measure_increment_gas_direct(counter_contract, acct_address: str,
                                  pre_address: str) -> int:
    """
    Use estimate_gas to measure Counter.increment() gas with the PRE contract
    as the simulated caller (bypassing the onlyOwner msg.sender check).
    This is deterministic: no ZKP randomness, no transaction overhead.
    """
    return counter_contract.functions.increment(acct_address).estimate_gas(
        {"from": pre_address}
    )


def benchmark(n_iters: int = 10):
    load_dotenv()
    rpc      = os.getenv("RPC_URL")
    chain_id = int(os.getenv("CHAIN_ID", "11155111"))
    pk       = os.getenv("PRIVATE_KEY")
    if not rpc or not pk:
        raise RuntimeError("Missing RPC_URL or PRIVATE_KEY in .env")

    w3 = Web3(Web3.HTTPProvider(rpc))
    if not w3.is_connected():
        raise RuntimeError("Web3 not connected; check RPC_URL")

    acct = Account.from_key(pk)
    abi, bytecode = load_pre_artifact()

    from CODeployment import ensure_sp_proof_material
    sp_proof_material = ensure_sp_proof_material(acct.address)

    # Shared ciphertext so Solidity's `hash = keccak(c1,c2,c3,c4) % PP` is
    # identical for both contracts → same FastEcMul cost for `hash * c2`.
    cipher_args = make_ciphertext_args()

    print("=" * 60)
    print("Deploying PRE WITH counting enabled ...")
    addr_with, counter_with_addr = deploy_pre(
        w3, acct, pk, chain_id, abi, bytecode, sp_proof_material,
        ciphertext_args=cipher_args, counting_enabled=True
    )

    print("Deploying PRE WITHOUT counting ...")
    addr_without, _counter_without_addr = deploy_pre(
        w3, acct, pk, chain_id, abi, bytecode, sp_proof_material,
        ciphertext_args=cipher_args, counting_enabled=False
    )
    print("=" * 60)

    counter_abi = load_counter_abi()
    counter_contract = w3.eth.contract(address=counter_with_addr, abi=counter_abi)

    # ------------------------------------------------------------------
    # Direct measurement 1: cold Counter.increment() via estimate_gas
    # Counter slot for acct.address is 0 before any reEncrypt call.
    # Simulate the call from the PRE contract (onlyOwner) without sending a tx.
    # ------------------------------------------------------------------
    cold_increment_gas = measure_increment_gas_direct(
        counter_contract, acct.address, addr_with
    )
    print(f"[direct] Counter.increment() gas (cold, 0→1): {cold_increment_gas}")

    contract_with    = w3.eth.contract(address=addr_with,    abi=abi)
    contract_without = w3.eth.contract(address=addr_without, abi=abi)

    sp = sp_module.SP()

    # rk1/rk2/rk3 are deterministic from system_parameters.json; generate once
    # so both contracts in every iteration use the same scalars in FastEcMul.
    rk1_raw, rk2_raw, rk3_raw = sp.rekeygenerate()
    rk1 = sp_module.mpz_to_uint256(rk1_raw)
    rk2 = sp_module.mpz_to_uint256(rk2_raw)
    rk3 = sp_module.mpz_to_uint256(rk3_raw)

    rows = []
    warm_increment_gas = None

    for i in range(n_iters):
        params_with    = make_reencrypt_params(sp, addr_with,    acct.address, rk1, rk2, rk3)
        params_without = make_reencrypt_params(sp, addr_without, acct.address, rk1, rk2, rk3)

        gas_with    = send_reencrypt(w3, contract_with,    acct, pk, chain_id, params_with)
        gas_without = send_reencrypt(w3, contract_without, acct, pk, chain_id, params_without)
        delta       = gas_with - gas_without

        rows.append((i + 1, gas_with, gas_without, delta))
        print(f"[{i+1}/{n_iters}]  gas_with={gas_with}  gas_without={gas_without}  delta={delta:+d}")

        # After the first reEncrypt the counter is at 1; measure warm cost once.
        if i == 0:
            warm_increment_gas = measure_increment_gas_direct(
                counter_contract, acct.address, addr_with
            )
            print(f"[direct] Counter.increment() gas (warm, 1→2): {warm_increment_gas}")

    # Write CSV
    with open(OUT_CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["iteration", "gas_with_counting", "gas_without_counting", "delta_gas"])
        writer.writerows(rows)

    gas_with_vals    = [r[1] for r in rows]
    gas_without_vals = [r[2] for r in rows]
    delta_vals       = [r[3] for r in rows]
    mean_reencrypt   = statistics.mean(gas_with_vals)

    print("=" * 60)
    print("Counter.increment() gas (direct estimate_gas measurement):")
    print(f"  cold (0→1):  {cold_increment_gas} gas")
    print(f"  warm (n→n+1): {warm_increment_gas} gas")
    if mean_reencrypt > 0:
        print(f"  reEncrypt mean (with counting): {mean_reencrypt:.0f} gas")
        print(f"  cold overhead %: {cold_increment_gas/mean_reencrypt*100:.2f}%")
        print(f"  warm overhead %: {warm_increment_gas/mean_reencrypt*100:.2f}%")
    print()
    print(f"Differential measurement over {n_iters} iterations (supporting data):")
    print(f"  gas_with    mean={statistics.mean(gas_with_vals):.0f}"
          f"  stdev={statistics.stdev(gas_with_vals) if n_iters > 1 else 0:.1f}")
    print(f"  gas_without mean={statistics.mean(gas_without_vals):.0f}"
          f"  stdev={statistics.stdev(gas_without_vals) if n_iters > 1 else 0:.1f}")
    print(f"  delta        mean={statistics.mean(delta_vals):.0f}"
          f"  stdev={statistics.stdev(delta_vals) if n_iters > 1 else 0:.1f}"
          f"  (note: variance from ZKP Schnorr proof randomness)")
    print(f"  Output written to: {OUT_CSV}")
    print("=" * 60)

    summary = {
        "label": "increment_isolation",
        "description": "Gas cost of Counter.increment() measured directly via estimate_gas "
                        "and confirmed by differential reEncrypt measurement",
        "n_iters": n_iters,
        "increment_gas_cold": cold_increment_gas,
        "increment_gas_warm": warm_increment_gas,
        "gas_with_counting_mean":    statistics.mean(gas_with_vals),
        "gas_without_counting_mean": statistics.mean(gas_without_vals),
        "delta_mean":  statistics.mean(delta_vals),
        "delta_stdev": statistics.stdev(delta_vals) if n_iters > 1 else 0,
        "pre_with_address":    addr_with,
        "pre_without_address": addr_without,
    }
    GasReportStore(GAS_REPORT_FILE).append(summary)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Isolate gas cost of Counter.increment()")
    parser.add_argument("--iters", type=int, default=10, help="Number of reEncrypt iterations per contract (default: 10)")
    args = parser.parse_args()
    benchmark(n_iters=args.iters)
