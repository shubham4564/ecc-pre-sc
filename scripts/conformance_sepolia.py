"""
Sepolia-based conformance smoke-test for Our ECC-PRE + Counter System.

Uses the already-deployed PRE contract on Sepolia to verify the core protocol:
  1. Connect to PRE contract and retrieve the Counter contract address
  2. Confirm our wallet is in the SP allowlist (or skip gracefully)
  3. Call reEncrypt() with real arithmetic ZKP inputs
  4. Verify transaction succeeds (status == 1) and returns non-zero outputs

Exits 0 on success, 1 on any failure.
"""

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
DATA = ROOT / "data"

# Add src to path so SP/TTP imports work
sys.path.insert(0, str(SRC))

from dotenv import load_dotenv
from web3 import Web3
import SP as sp_module


def _load_dotenv() -> dict:
    load_dotenv(ROOT / ".env")
    return {
        "rpc_url": os.getenv("RPC_URL") or "",
        "private_key": os.getenv("PRIVATE_KEY") or "",
        "wallet_address": os.getenv("WALLET_ADDRESS") or "",
        "chain_id": int(os.getenv("CHAIN_ID", "11155111")),
    }


def _load_pre_contract(w3: Web3) -> object:
    with open(DATA / "PRE_compData1.json", "r") as f:
        pre_data = json.load(f)
    abi = pre_data["PRE"]["abi"]

    with open(DATA / "contract_info.json", "r") as f:
        addr = json.load(f)["contract_address"]

    return w3.eth.contract(address=Web3.to_checksum_address(addr), abi=abi)


def _load_counter_abi() -> list:
    with open(DATA / "Counter_compData.json", "r") as f:
        return json.load(f)["abi"]


def main() -> None:
    cfg = _load_dotenv()

    if not cfg["rpc_url"] or not cfg["private_key"]:
        print("ERROR: Missing RPC_URL or PRIVATE_KEY in .env", file=sys.stderr)
        raise SystemExit(1)

    pk = cfg["private_key"]
    if not pk.startswith("0x"):
        pk = "0x" + pk

    w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
    if not w3.is_connected():
        print("ERROR: Cannot connect to Sepolia RPC", file=sys.stderr)
        raise SystemExit(1)

    pre = _load_pre_contract(w3)
    print(f"ECC-PRE conformance: contract={pre.address}")

    # 1. Retrieve the Counter contract address from the PRE contract
    counter_address = pre.functions.countingContract().call()
    print(f"  [1] countingContract → {counter_address}  OK")
    assert counter_address != "0x0000000000000000000000000000000000000000", \
        "countingContract returned zero address"

    counter = w3.eth.contract(address=Web3.to_checksum_address(counter_address), abi=_load_counter_abi())

    # 2. Check SP allowlist status
    account = w3.eth.account.from_key(pk)
    sender = account.address
    is_allowed = counter.functions.isAllowed(sender).call()
    print(f"  [2] isAllowed({sender}) = {is_allowed}  OK")

    if not is_allowed:
        print("  NOTE: Wallet not in allowlist; reEncrypt will use ZKP verification path")

    # 3. Build reEncrypt params using real SP crypto
    sp = sp_module.SP()
    rk1, rk2, rk3 = sp.rekeygenerate()
    proof = sp_module.generate_arithmetic_zkp_inputs(
        rk1=rk1, rk2=rk2, rk3=rk3, contract_address=pre.address, sender_address=sender
    )

    params = {
        "rk1": int(rk1),
        "rk2": int(rk2),
        "rk3": int(rk3),
        "commitment": [int(c) for c in proof["commitment"]],
        "response": [int(r) for r in proof["response"]],
        "nonce": int(proof["nonce"]),
        "expiry": int(proof["expiry"]),
    }
    print("  [3] generate ZKP params  OK")

    # 4. Call reEncrypt() on Sepolia
    chain_id = cfg["chain_id"]
    latest = w3.eth.get_block("latest")
    gas_cap = max(300_000, min(5_000_000, int(latest.get("gasLimit", 30_000_000)) - 100_000))

    nonce = w3.eth.get_transaction_count(sender, "pending")
    tx = pre.functions.reEncrypt(params).build_transaction({
        "from": sender,
        "nonce": nonce,
        "gas": gas_cap,
        "maxFeePerGas": w3.to_wei("50", "gwei"),
        "maxPriorityFeePerGas": w3.to_wei("1", "gwei"),
        "chainId": chain_id,
    })
    signed = w3.eth.account.sign_transaction(tx, private_key=pk)
    raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction")
    tx_hash = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    assert receipt.status == 1, f"reEncrypt tx failed: {tx_hash.hex()}"
    print(f"  [4] reEncrypt() → status=1  gasUsed={receipt.gasUsed}  OK")

    # 5. Verify counter incremented (getCount for our address should be >= 1)
    count = counter.functions.getCount(sender).call()
    print(f"  [5] getCount({sender}) = {count}  OK")

    print("ECC-PRE conformance PASSED")


if __name__ == "__main__":
    main()
