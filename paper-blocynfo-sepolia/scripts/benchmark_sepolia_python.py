import csv
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from web3 import Web3

from deploy_sepolia_python import pick_config, compile_contracts, artifact
from offchain_helpers import canonical_attr_hash, policy_hash, cti_hash, derive_rekey_hash, derive_rekey_blob


def load_deployed(project_dir: Path):
    p = project_dir / "data" / "deployed.sepolia.json"
    if not p.exists():
        raise RuntimeError(f"Missing deployed file: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def sign_send_wait(w3: Web3, private_key: str, tx: Dict[str, Any]) -> Tuple[Dict[str, Any], float]:
    t0 = time.perf_counter()
    signed = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    rcpt = dict(w3.eth.wait_for_transaction_receipt(tx_hash))
    return rcpt, (time.perf_counter() - t0) * 1000.0


def summarize(rows: List[Tuple[int, str, int, float, str]]):
    agg = {}
    for _, op, gas, ms, _ in rows:
        agg.setdefault(op, {"gas": [], "ms": []})
        agg[op]["gas"].append(gas)
        agg[op]["ms"].append(ms)

    out = []
    for op, v in agg.items():
        out.append(
            {
                "operation": op,
                "count": len(v["gas"]),
                "gas_mean": sum(v["gas"]) / len(v["gas"]),
                "gas_min": min(v["gas"]),
                "gas_max": max(v["gas"]),
                "latency_ms_mean": sum(v["ms"]) / len(v["ms"]),
                "latency_ms_min": min(v["ms"]),
                "latency_ms_max": max(v["ms"]),
            }
        )
    return out


def main() -> None:
    cfg = pick_config()
    project_dir = Path(cfg["project_dir"])
    deployed = load_deployed(project_dir)

    w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
    if not w3.is_connected():
        raise RuntimeError("RPC connection failed")

    abi = artifact(compile_contracts(project_dir), "contracts/BloCyNfoShare.sol", "BloCyNfoShare")["abi"]
    c = w3.eth.contract(address=Web3.to_checksum_address(deployed["bloCyNfoShare"]), abi=abi)

    account = w3.eth.account.from_key(cfg["private_key"])
    nonce = w3.eth.get_transaction_count(account.address)
    gp = w3.eth.gas_price
    iters = int(os.environ.get("BENCH_ITERS", "3"))

    rows: List[Tuple[int, str, int, float, str]] = []

    for i in range(1, iters + 1):
        params_hash = Web3.keccak(text=f"blc-params-{i}")
        tx = c.functions.storeParams(params_hash, f"ipfs://blocynfo/params/{i}").build_transaction(
            {"from": account.address, "nonce": nonce, "gas": 250000, "gasPrice": gp, "chainId": cfg["chain_id"]}
        )
        rcpt, ms = sign_send_wait(w3, cfg["private_key"], tx)
        rows.append((i, "storeParams", int(rcpt["gasUsed"]), ms, rcpt["transactionHash"].hex()))
        nonce += 1

        tx = c.functions.orgRegistration(
            Web3.keccak(text=f"ORG:{account.address}:{i}"),
            int.from_bytes(Web3.keccak(text=f"pk-{i}"), "big"),
            Web3.keccak(text=f"creds-{i}"),
            canonical_attr_hash(["security manager", "health", "us"]),
        ).build_transaction({"from": account.address, "nonce": nonce, "gas": 350000, "gasPrice": gp, "chainId": cfg["chain_id"]})
        rcpt, ms = sign_send_wait(w3, cfg["private_key"], tx)
        rows.append((i, "orgRegistration", int(rcpt["gasUsed"]), ms, rcpt["transactionHash"].hex()))
        nonce += 1

        tx = c.functions.approveOrganization(account.address, True, True).build_transaction(
            {"from": account.address, "nonce": nonce, "gas": 120000, "gasPrice": gp, "chainId": cfg["chain_id"]}
        )
        rcpt, ms = sign_send_wait(w3, cfg["private_key"], tx)
        rows.append((i, "approveOrganization", int(rcpt["gasUsed"]), ms, rcpt["transactionHash"].hex()))
        nonce += 1

        qpk = int.from_bytes(Web3.keccak(text=f"qpk-{i}"), "big")
        tx = c.functions.regPubKey(qpk, Web3.keccak(text=f"signed-qpk-{i}")).build_transaction(
            {"from": account.address, "nonce": nonce, "gas": 180000, "gasPrice": gp, "chainId": cfg["chain_id"]}
        )
        rcpt, ms = sign_send_wait(w3, cfg["private_key"], tx)
        rows.append((i, "regPubKey", int(rcpt["gasUsed"]), ms, rcpt["transactionHash"].hex()))
        nonce += 1

        cti_id = Web3.keccak(text=f"cti:{account.address}:{i}")
        p_hash = policy_hash({"op": "AND", "children": ["security manager", "health", "us"]})
        c_hash = cti_hash(f"cti-{i}".encode("utf-8"))

        tx = c.functions.hashCTI(cti_id, c_hash, p_hash, f"ipfs://blocynfo/cti/{i}").build_transaction(
            {"from": account.address, "nonce": nonce, "gas": 250000, "gasPrice": gp, "chainId": cfg["chain_id"]}
        )
        rcpt, ms = sign_send_wait(w3, cfg["private_key"], tx)
        rows.append((i, "hashCTI", int(rcpt["gasUsed"]), ms, rcpt["transactionHash"].hex()))
        nonce += 1

        rk_hash = derive_rekey_hash(cfg["private_key"], qpk, p_hash)
        rk_blob = derive_rekey_blob(cfg["private_key"], qpk, p_hash)
        tx = c.functions.storeReKey(cti_id, account.address, rk_hash, rk_blob).build_transaction(
            {"from": account.address, "nonce": nonce, "gas": 300000, "gasPrice": gp, "chainId": cfg["chain_id"]}
        )
        rcpt, ms = sign_send_wait(w3, cfg["private_key"], tx)
        rows.append((i, "storeReKey", int(rcpt["gasUsed"]), ms, rcpt["transactionHash"].hex()))
        nonce += 1

        ok = c.functions.verify(cti_id, account.address, c_hash, rk_hash).call()
        if not ok:
            raise RuntimeError("verify() returned false in benchmark")

    bench_dir = project_dir / "benchmarks"
    detail = bench_dir / "paper_blocynfo_sepolia_detail.csv"
    summary = bench_dir / "paper_blocynfo_sepolia_summary.csv"

    with detail.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["iteration", "operation", "gas_used", "latency_ms", "tx_hash"])
        w.writerows(rows)

    summary_rows = summarize(rows)
    with summary.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
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
        w.writeheader()
        w.writerows(summary_rows)

    print(f"Saved detail: {detail}")
    print(f"Saved summary: {summary}")
    print(json.dumps(summary_rows, indent=2))


if __name__ == "__main__":
    main()
