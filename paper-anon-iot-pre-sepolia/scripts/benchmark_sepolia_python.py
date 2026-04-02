import csv
import os
from pathlib import Path
from typing import Dict, List

from web3 import Web3

from common import artifact, compile_contracts, execute_fn, load_deployment, now_ms, pick_config, summary_from_detail, write_csv
from offchain_helpers import derive_rekey_commitment, derive_transformed_cipher_hash, pseudonym, stable_cipher_hash


def read_total(path: Path, gas_col: str, lat_col: str) -> tuple[float | None, float | None]:
    if not path.exists():
        return None, None
    gas_total = 0.0
    lat_total = 0.0
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return None, None
        for row in reader:
            gas_total += float(row.get(gas_col, "0") or 0.0)
            lat_total += float(row.get(lat_col, "0") or 0.0)
    return gas_total, lat_total


def main() -> None:
    project_dir = Path(__file__).resolve().parents[1]
    cfg = pick_config(project_dir)

    if not cfg["rpc_url"]:
        raise RuntimeError("Missing RPC_URL or ALCHEMY_SEPOLIA_URL")
    if not cfg["private_key"]:
        raise RuntimeError("Missing PRIVATE_KEY or DEPLOYER_PRIVATE_KEY")

    iters = int(os.environ.get("BENCH_ITERS", "3"))

    w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
    if not w3.is_connected():
        raise RuntimeError("RPC connection failed")

    deploy = load_deployment(project_dir)
    compiled = compile_contracts(project_dir)

    art = artifact(compiled, "contracts/IoTAnonymousPRE.sol", "IoTAnonymousPRE")
    c = w3.eth.contract(address=deploy["iotAnonymousPre"], abi=art["abi"])

    owner_pk = cfg["private_key"]
    owner = w3.eth.account.from_key(owner_pk)

    device_pk = cfg["query_private_key"] or owner_pk
    device = w3.eth.account.from_key(device_pk)

    rows: List[Dict[str, object]] = []

    for i in range(1, iters + 1):
        owner_pseudo = pseudonym(f"owner:{owner.address}:{i}")
        device_pseudo = pseudonym(f"device:{device.address}:{i}")

        t0 = now_ms()
        rcpt = execute_fn(w3, c.functions.registerOwner(owner_pseudo), owner_pk, cfg["chain_id"])
        t1 = now_ms()
        rows.append({"operation": "registerOwner", "iteration": i, "tx_hash": rcpt["transactionHash"].hex(), "gas_used": rcpt["gasUsed"], "latency_ms": t1 - t0})

        t0 = now_ms()
        rcpt = execute_fn(
            w3,
            c.functions.registerDevice(owner_pseudo, device_pseudo, device.address),
            owner_pk,
            cfg["chain_id"],
        )
        t1 = now_ms()
        rows.append({"operation": "registerDevice", "iteration": i, "tx_hash": rcpt["transactionHash"].hex(), "gas_used": rcpt["gasUsed"], "latency_ms": t1 - t0})

        cipher_hash = stable_cipher_hash(f"iot-cipher-{i}".encode("utf-8"))
        policy_hash = Web3.keccak(text=f"policy-{i}")

        t0 = now_ms()
        rcpt = execute_fn(w3, c.functions.authorizeData(device_pseudo, cipher_hash, policy_hash), owner_pk, cfg["chain_id"])
        t1 = now_ms()
        rows.append({"operation": "authorizeData", "iteration": i, "tx_hash": rcpt["transactionHash"].hex(), "gas_used": rcpt["gasUsed"], "latency_ms": t1 - t0})

        data_id = Web3.solidity_keccak(["bytes32", "bytes32", "bytes32", "bytes32"], [owner_pseudo, device_pseudo, cipher_hash, policy_hash])
        rekey_commit = derive_rekey_commitment(owner_pk, data_id)

        t0 = now_ms()
        rcpt = execute_fn(w3, c.functions.submitReKey(data_id, rekey_commit), owner_pk, cfg["chain_id"])
        t1 = now_ms()
        rows.append({"operation": "submitReKey", "iteration": i, "tx_hash": rcpt["transactionHash"].hex(), "gas_used": rcpt["gasUsed"], "latency_ms": t1 - t0})

        request_nonce = Web3.keccak(text=f"req-{i}")
        t0 = now_ms()
        rcpt = execute_fn(w3, c.functions.requestReEncryption(data_id, request_nonce), device_pk, cfg["chain_id"])
        t1 = now_ms()
        rows.append({"operation": "requestReEncryption", "iteration": i, "tx_hash": rcpt["transactionHash"].hex(), "gas_used": rcpt["gasUsed"], "latency_ms": t1 - t0})

        request_id = Web3.solidity_keccak(["bytes32", "address", "bytes32"], [data_id, device.address, request_nonce])
        transformed_hash = derive_transformed_cipher_hash(cipher_hash, rekey_commit, request_nonce)

        t0 = now_ms()
        rcpt = execute_fn(w3, c.functions.approveReEncryption(request_id, transformed_hash), owner_pk, cfg["chain_id"])
        t1 = now_ms()
        rows.append({"operation": "approveReEncryption", "iteration": i, "tx_hash": rcpt["transactionHash"].hex(), "gas_used": rcpt["gasUsed"], "latency_ms": t1 - t0})

    detail_path = project_dir / "benchmarks" / "paper_anon_iot_pre_sepolia_detail.csv"
    summary_path = project_dir / "benchmarks" / "paper_anon_iot_pre_sepolia_summary.csv"

    write_csv(detail_path, rows, ["operation", "iteration", "tx_hash", "gas_used", "latency_ms"])

    summary_rows = summary_from_detail(rows)
    write_csv(
        summary_path,
        summary_rows,
        ["operation", "count", "gas_mean", "gas_min", "gas_max", "latency_ms_mean", "latency_ms_min", "latency_ms_max"],
    )

    total_gas = sum(float(r["gas_mean"]) for r in summary_rows)
    total_lat = sum(float(r["latency_ms_mean"]) for r in summary_rows)

    existing_path = project_dir.parent / "benchmarks" / "all_impl_comparison_gas_time.csv"
    rows_comp: List[Dict[str, object]] = [{
        "implementation": "paper_anon_iot_pre_sepolia",
        "total_gas": total_gas,
        "total_latency_ms": total_lat,
    }]

    if existing_path.exists():
        with existing_path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows_comp.append(
                    {
                        "implementation": row.get("implementation", ""),
                        "total_gas": float(row.get("total_gas", "0") or 0),
                        "total_latency_ms": float(row.get("total_latency_ms", "0") or 0),
                    }
                )

    comp_path = project_dir / "benchmarks" / "comparison_with_existing_and_other_papers.csv"
    rows_comp_sorted = sorted(rows_comp, key=lambda x: float(x["total_gas"]))
    write_csv(comp_path, rows_comp_sorted, ["implementation", "total_gas", "total_latency_ms"])

    print(f"Saved detail: {detail_path}")
    print(f"Saved summary: {summary_path}")
    print(f"Saved comparison: {comp_path}")


if __name__ == "__main__":
    main()
