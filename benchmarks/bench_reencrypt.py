import os, json, csv, time, statistics, sys, pathlib
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv

# Paths relative to this file
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
ARTIFACT_PRE = os.path.join(ROOT, "artifacts", "PRE.json")
CONTRACT_INFO = os.path.join(ROOT, "data", "contract_info.json")
OUT_CSV  = os.path.join(os.path.dirname(__file__), "reencrypt_bench.csv")


# Ensure project root is importable to reuse your off-chain pipeline
ROOT_PATH = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT_PATH / "src") not in sys.path:
    sys.path.insert(0, str(ROOT_PATH / "src"))

try:
    import SP as sp_module
except ModuleNotFoundError:
    # Fallback dynamic import if running from unusual cwd
    import importlib.util
    spec = importlib.util.spec_from_file_location("SP", str(ROOT_PATH / "src" / "SP.py"))
    sp_module = importlib.util.module_from_spec(spec)
    sys.modules["SP"] = sp_module
    assert spec.loader is not None
    spec.loader.exec_module(sp_module)


def load_contract(w3: Web3):
    with open(ARTIFACT_PRE, "r") as f:
        pre = json.load(f)
    abi = pre["abi"]

    with open(CONTRACT_INFO, "r") as f:
        addr = json.load(f)["contract_address"]
    address = Web3.to_checksum_address(addr)
    return w3.eth.contract(address=address, abi=abi)


def send_reencrypt(w3: Web3, contract, from_addr, pk, chain_id, params):
    latest = w3.eth.get_block('latest')
    block_gas_limit = int(latest.get('gasLimit', 30_000_000))
    gas_cap = max(300_000, min(5_000_000, block_gas_limit - 100_000))
    tx = contract.functions.reEncrypt(params).build_transaction({
        "from": from_addr,
        # Use 'pending' to account for transactions already in-flight
        "nonce": w3.eth.get_transaction_count(from_addr, 'pending'),
        "gas": gas_cap,
        "maxFeePerGas": w3.to_wei("50", "gwei"),
        "maxPriorityFeePerGas": w3.to_wei("1", "gwei"),
        "chainId": chain_id,
    })
    signed = w3.eth.account.sign_transaction(tx, private_key=pk)
    # Web3.py v5 uses camelCase rawTransaction; v6 uses snake_case raw_transaction
    raw_tx = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction")
    t0 = time.perf_counter_ns()
    tx_hash = w3.eth.send_raw_transaction(raw_tx)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    t1 = time.perf_counter_ns()
    if getattr(receipt, 'status', receipt.get('status', 0)) != 1:
        raise RuntimeError(f"reEncrypt tx failed: {tx_hash.hex()} | receipt={receipt}")
    return receipt.gasUsed, (t1 - t0) / 1e6  # gas, latency_ms


def make_real_params():
    """Produce the exact inputs your app passes to reEncrypt using SP.py helpers."""
    sp = sp_module.SP()
    # Re-encryption keys (rk1,rk2,rk3)
    rk1, rk2, rk3 = sp.rekeygenerate()

    # Generate commitments and proof inputs mirroring SP.main() flow
    # Small sizes are sufficient for proof check and match existing usage in SP.py
    i = sp_module.generate_large_prime(20)
    o = sp_module.generate_large_prime(20)
    bytesize = 20
    j = sp_module.get_rand(bytesize)
    v = sp_module.get_rand(bytesize)
    w = sp_module.generate_large_prime(10)
    y, z, A, B = sp_module.computeCommitment(i, o, j, v, w)
    gamma = sp_module.computeChallenge(i, y, o, z, A, B, w)
    alpha = sp_module.computeProof(j, gamma, v, w)

    # All values must be uint256-compatible ints (they already are)
    return {
        "rk1": int(rk1),
        "rk2": int(rk2),
        "rk3": int(rk3),
        "i": int(i),
        "o": int(o),
        "y": int(y),
        "z": int(z),
        "w": int(w),
        "alpha": int(alpha),
        "gamma": int(gamma),
    }


def benchmark(n_iters=20):
    load_dotenv()
    rpc = os.getenv("RPC_URL")
    chain_id = int(os.getenv("CHAIN_ID", "11155111"))  # default: Sepolia
    pk = os.getenv("PRIVATE_KEY")
    if not rpc or not pk:
        raise RuntimeError("Missing RPC_URL or PRIVATE_KEY in .env")

    w3 = Web3(Web3.HTTPProvider(rpc))
    if not w3.is_connected():
        raise RuntimeError("Web3 not connected; check RPC_URL")

    acct = Account.from_key(pk)
    contract = load_contract(w3)

    rows = []
    for i in range(n_iters):
        params = make_real_params()
        gas, lat_ms = send_reencrypt(w3, contract, acct.address, pk, chain_id, params)
        rows.append((gas, lat_ms))
        print(f"[{i+1}/{n_iters}] gas={gas}, latency_ms={lat_ms:.2f}")

    with open(OUT_CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["gas_used", "latency_ms"])
        writer.writerows(rows)

    gas_vals = [g for g, _ in rows]
    lat_vals = [l for _, l in rows]
    print(f"gas avg: {statistics.mean(gas_vals):.0f}")
    print(f"lat avg (ms): {statistics.mean(lat_vals):.2f}")

    # Quick percentiles
    for p in [50, 90, 99]:
        idx = max(0, min(99, p-1))
        print(f"lat p{p} (ms): {statistics.quantiles(lat_vals, n=100)[idx]:.2f}")

    # Approx throughput across total wall time
    total_time_s = sum(lat_vals) / 1000.0
    tps = len(rows) / total_time_s if total_time_s > 0 else 0
    print(f"throughput (tx/s, approx): {tps:.3f}")


if __name__ == "__main__":
    benchmark(5)
