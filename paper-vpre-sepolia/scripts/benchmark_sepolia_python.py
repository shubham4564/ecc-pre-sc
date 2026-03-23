import csv
import json
import os
import time
from pathlib import Path
from typing import Dict, Tuple, Any

from web3 import Web3

from deploy_sepolia_python import pick_config, compile_contracts, get_artifact
from offchain_utils import key_gen, compute_rk, compute_vk


def load_deployed(project_dir: Path) -> Dict[str, Any]:
    p = project_dir / "data" / "deployed.sepolia.json"
    if not p.exists():
        raise RuntimeError(f"Missing deployed file: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def send_and_measure(w3: Web3, private_key: str, tx: Dict[str, Any]) -> Tuple[Dict[str, Any], float]:
    t0 = time.perf_counter()
    signed = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return dict(receipt), elapsed_ms


def build_tx(base: Dict[str, Any], nonce: int, gas: int, gas_price: int) -> Dict[str, Any]:
    base["nonce"] = nonce
    base["gas"] = gas
    base["gasPrice"] = gas_price
    return base


def run_iteration(w3: Web3, cfg: Dict[str, Any], abis: Dict[str, Any], addrs: Dict[str, str], nonce: int, idx: int):
    account = w3.eth.account.from_key(cfg["private_key"])
    gas_price = w3.eth.gas_price

    auth = w3.eth.contract(address=Web3.to_checksum_address(addrs["authentication"]), abi=abis["auth"])
    dl = w3.eth.contract(address=Web3.to_checksum_address(addrs["dataList"]), abi=abis["dl"])
    ff = w3.eth.contract(address=Web3.to_checksum_address(addrs["fundFlow"]), abi=abis["ff"])
    tr = w3.eth.contract(address=Web3.to_checksum_address(addrs["trading"]), abi=abis["tr"])

    ds = key_gen()
    db = key_gen()

    submission_id = Web3.to_hex(Web3.solidity_keccak(["address", "uint256", "uint256"], [account.address, idx, int(time.time() * 1e6)]))
    dd_hash = Web3.to_hex(Web3.solidity_keccak(["string"], [f"benchmark-dd-{idx}"]))

    rows = []

    tx = auth.functions.submitForAuthentication(
        submission_id,
        ds["pk"],
        b"mock-Cfk",
        dd_hash,
    ).build_transaction(build_tx({"from": account.address, "chainId": cfg["chain_id"]}, nonce, 500_000, gas_price))
    r, ms = send_and_measure(w3, cfg["private_key"], tx)
    rows.append((idx, "submitForAuthentication", r["gasUsed"], ms, Web3.to_hex(r["transactionHash"])))
    nonce += 1

    tx = auth.functions.authenticateData(
        submission_id,
        b"mock-Ckey",
        f"ipfs://benchmark-{idx}",
    ).build_transaction(build_tx({"from": account.address, "chainId": cfg["chain_id"]}, nonce, 700_000, gas_price))
    r, ms = send_and_measure(w3, cfg["private_key"], tx)
    rows.append((idx, "authenticateData", r["gasUsed"], ms, Web3.to_hex(r["transactionHash"])))
    nonce += 1

    events = auth.events.ProductAuthenticated().process_receipt(r)
    if not events:
        raise RuntimeError("Missing ProductAuthenticated event")
    uid = int(events[0]["args"]["uid"])

    tx = dl.functions.listData(uid, 1).build_transaction(build_tx({"from": account.address, "chainId": cfg["chain_id"]}, nonce, 300_000, gas_price))
    r, ms = send_and_measure(w3, cfg["private_key"], tx)
    rows.append((idx, "listData", r["gasUsed"], ms, Web3.to_hex(r["transactionHash"])))
    nonce += 1

    tx = ff.functions.deposit(uid).build_transaction(build_tx({"from": account.address, "chainId": cfg["chain_id"], "value": 1}, nonce, 400_000, gas_price))
    r, ms = send_and_measure(w3, cfg["private_key"], tx)
    rows.append((idx, "deposit", r["gasUsed"], ms, Web3.to_hex(r["transactionHash"])))
    nonce += 1

    sk_e = key_gen()["sk"]
    rk_out = compute_rk(ds["sk"], db["pk"], sk_e)
    vk_out = compute_vk(ds["pk"], db["pk"], db["sk"], rk_out["pk_e"])

    tx = tr.functions.submitCmit(uid, ds["pk"], db["pk"], rk_out["pk_e"], rk_out["cmit"]).build_transaction(
        build_tx({"from": account.address, "chainId": cfg["chain_id"]}, nonce, 350_000, gas_price)
    )
    r, ms = send_and_measure(w3, cfg["private_key"], tx)
    rows.append((idx, "submitCmit", r["gasUsed"], ms, Web3.to_hex(r["transactionHash"])))
    nonce += 1

    tx = tr.functions.submitVK(uid, vk_out["vk"]).build_transaction(build_tx({"from": account.address, "chainId": cfg["chain_id"]}, nonce, 350_000, gas_price))
    r, ms = send_and_measure(w3, cfg["private_key"], tx)
    rows.append((idx, "submitVK", r["gasUsed"], ms, Web3.to_hex(r["transactionHash"])))
    nonce += 1

    tx = tr.functions.settlement(uid, rk_out["rk"]).build_transaction(build_tx({"from": account.address, "chainId": cfg["chain_id"]}, nonce, 1_000_000, gas_price))
    r, ms = send_and_measure(w3, cfg["private_key"], tx)
    rows.append((idx, "settlement", r["gasUsed"], ms, Web3.to_hex(r["transactionHash"])))
    nonce += 1

    return rows, nonce


def summarize(rows):
    by_op = {}
    for _, op, gas, ms, _ in rows:
        by_op.setdefault(op, {"gas": [], "ms": []})
        by_op[op]["gas"].append(int(gas))
        by_op[op]["ms"].append(float(ms))

    summary = []
    for op, vals in by_op.items():
        gas_vals = vals["gas"]
        ms_vals = vals["ms"]
        summary.append(
            {
                "operation": op,
                "count": len(gas_vals),
                "gas_mean": sum(gas_vals) / len(gas_vals),
                "gas_min": min(gas_vals),
                "gas_max": max(gas_vals),
                "latency_ms_mean": sum(ms_vals) / len(ms_vals),
                "latency_ms_min": min(ms_vals),
                "latency_ms_max": max(ms_vals),
            }
        )
    return summary


def main():
    cfg = pick_config()
    project_dir = Path(cfg["project_dir"])
    deployed = load_deployed(project_dir)

    w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
    if not w3.is_connected():
        raise RuntimeError("RPC connection failed")

    compiled = compile_contracts(project_dir)
    abis = {
        "auth": get_artifact(compiled, "contracts/Authentication.sol", "Authentication")["abi"],
        "dl": get_artifact(compiled, "contracts/DataList.sol", "DataList")["abi"],
        "ff": get_artifact(compiled, "contracts/FundFlow.sol", "FundFlow")["abi"],
        "tr": get_artifact(compiled, "contracts/Trading.sol", "Trading")["abi"],
    }

    addrs = {
        "authentication": deployed["authentication"],
        "dataList": deployed["dataList"],
        "fundFlow": deployed["fundFlow"],
        "trading": deployed["trading"],
    }

    iters = int(os.environ.get("BENCH_ITERS", "3"))
    account = w3.eth.account.from_key(cfg["private_key"])
    nonce = w3.eth.get_transaction_count(account.address)

    all_rows = []
    for i in range(1, iters + 1):
        rows, nonce = run_iteration(w3, cfg, abis, addrs, nonce, i)
        all_rows.extend(rows)

    bench_dir = project_dir / "benchmarks"
    bench_dir.mkdir(parents=True, exist_ok=True)

    detail_csv = bench_dir / "paper_vpre_sepolia_detail.csv"
    with detail_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["iteration", "operation", "gas_used", "latency_ms", "tx_hash"])
        writer.writerows(all_rows)

    summary_rows = summarize(all_rows)
    summary_csv = bench_dir / "paper_vpre_sepolia_summary.csv"
    with summary_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "operation",
                "count",
                "gas_mean",
                "gas_min",
                "gas_max",
                "latency_ms_mean",
                "latency_ms_min",
                "latency_ms_max",
            ],
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    print(f"Saved detail: {detail_csv}")
    print(f"Saved summary: {summary_csv}")
    print(json.dumps(summary_rows, indent=2))


if __name__ == "__main__":
    main()
