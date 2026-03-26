import csv
import os
from pathlib import Path
from typing import Dict, List

from web3 import Web3

from common import (
    artifact,
    compile_contracts,
    compute_label,
    execute_fn,
    load_deployment,
    now_ms,
    pick_config,
    summary_from_detail,
    write_csv,
)


def read_existing_total_gas(path: Path) -> float | None:
    if not path.exists():
        return None
    total = 0.0
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return None
        if "gas_mean" in reader.fieldnames:
            for row in reader:
                total += float(row.get("gas_mean", "0") or 0.0)
            return total
        if "gas_used" in reader.fieldnames:
            for row in reader:
                total += float(row.get("gas_used", "0") or 0.0)
            return total
    return None


def read_existing_total_latency_ms(path: Path) -> float | None:
    if not path.exists():
        return None
    total = 0.0
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return None
        if "latency_ms_mean" in reader.fieldnames:
            for row in reader:
                total += float(row.get("latency_ms_mean", "0") or 0.0)
            return total
        if "time_ms" in reader.fieldnames:
            for row in reader:
                total += float(row.get("time_ms", "0") or 0.0)
            return total
    return None


def read_existing_from_prior_comparison(path: Path, metric: str) -> float | None:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row_metric = row.get("metric") or row.get("\ufeffmetric")
            if row_metric == metric:
                val = row.get("existing_ecc_pre", "")
                if val:
                    return float(val)
    return None


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
    se = artifact(compiled, "contracts/SENSHSearchableEncryption.sol", "SENSHSearchableEncryption")
    contract = w3.eth.contract(address=deploy["senshSearchableEncryption"], abi=se["abi"])

    owner = w3.eth.account.from_key(cfg["private_key"])
    query_pk = cfg["query_private_key"] or cfg["private_key"]
    query_user = w3.eth.account.from_key(query_pk)

    if query_user.address != owner.address and not contract.functions.isAuthorized(query_user.address).call():
        execute_fn(
            w3,
            contract.functions.authorizeUser(query_user.address),
            cfg["private_key"],
            cfg["chain_id"],
        )

    detail_rows: List[Dict[str, object]] = []
    key_material = "bench-master-key"

    for i in range(1, iters + 1):
        endata = f"patient-{i}:lab:glucose"
        reenc_value = Web3.keccak(text=f"reenc-{i}-v1")
        updated_value = Web3.keccak(text=f"reenc-{i}-v2")
        label = compute_label(key_material, endata)

        t0 = now_ms()
        rcpt = execute_fn(
            w3,
            contract.functions.generateLabel(key_material, endata, reenc_value),
            query_pk,
            cfg["chain_id"],
        )
        t1 = now_ms()
        detail_rows.append(
            {
                "operation": "generateLabel",
                "iteration": i,
                "tx_hash": rcpt["transactionHash"].hex(),
                "gas_used": rcpt["gasUsed"],
                "latency_ms": t1 - t0,
            }
        )

        t0 = now_ms()
        rcpt = execute_fn(w3, contract.functions.generateToken(label), query_pk, cfg["chain_id"])
        t1 = now_ms()
        detail_rows.append(
            {
                "operation": "generateToken",
                "iteration": i,
                "tx_hash": rcpt["transactionHash"].hex(),
                "gas_used": rcpt["gasUsed"],
                "latency_ms": t1 - t0,
            }
        )

        t0 = now_ms()
        rcpt = execute_fn(w3, contract.functions.search(label), query_pk, cfg["chain_id"])
        t1 = now_ms()
        detail_rows.append(
            {
                "operation": "search",
                "iteration": i,
                "tx_hash": rcpt["transactionHash"].hex(),
                "gas_used": rcpt["gasUsed"],
                "latency_ms": t1 - t0,
            }
        )

        t0 = now_ms()
        rcpt = execute_fn(w3, contract.functions.updateLabel(label, updated_value), query_pk, cfg["chain_id"])
        t1 = now_ms()
        detail_rows.append(
            {
                "operation": "updateLabel",
                "iteration": i,
                "tx_hash": rcpt["transactionHash"].hex(),
                "gas_used": rcpt["gasUsed"],
                "latency_ms": t1 - t0,
            }
        )

    detail_path = project_dir / "benchmarks" / "paper_sensh_sepolia_detail.csv"
    write_csv(detail_path, detail_rows, ["operation", "iteration", "tx_hash", "gas_used", "latency_ms"])

    summary_rows = summary_from_detail(detail_rows)
    summary_path = project_dir / "benchmarks" / "paper_sensh_sepolia_summary.csv"
    write_csv(
        summary_path,
        summary_rows,
        [
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

    sensh_total_gas = sum(float(r["gas_mean"]) for r in summary_rows)
    sensh_total_latency = sum(float(r["latency_ms_mean"]) for r in summary_rows)

    existing_summary = project_dir.parent / "benchmarks" / "timing_bench.csv"
    vpre_summary = project_dir.parent / "paper-vpre-sepolia" / "benchmarks" / "paper_vpre_sepolia_summary.csv"
    blocynfo_summary = project_dir.parent / "paper-blocynfo-sepolia" / "benchmarks" / "paper_blocynfo_sepolia_summary.csv"

    prior_comp = project_dir.parent / "paper-blocynfo-sepolia" / "benchmarks" / "comparison_with_existing_and_vpre.csv"

    existing_gas = read_existing_total_gas(existing_summary)
    if existing_gas is None:
        existing_gas = read_existing_from_prior_comparison(prior_comp, "end_to_end_gas")

    existing_latency = read_existing_total_latency_ms(existing_summary)
    prior_latency = read_existing_from_prior_comparison(prior_comp, "end_to_end_latency_ms")
    if prior_latency is not None:
        existing_latency = prior_latency

    comparison_rows = [
        {
            "metric": "end_to_end_gas",
            "paper_sensh_sepolia": sensh_total_gas,
            "paper_vpre_sepolia": read_existing_total_gas(vpre_summary),
            "paper_blocynfo_sepolia": read_existing_total_gas(blocynfo_summary),
            "existing_ecc_pre": existing_gas,
        },
        {
            "metric": "end_to_end_latency_ms",
            "paper_sensh_sepolia": sensh_total_latency,
            "paper_vpre_sepolia": read_existing_total_latency_ms(vpre_summary),
            "paper_blocynfo_sepolia": read_existing_total_latency_ms(blocynfo_summary),
            "existing_ecc_pre": existing_latency,
        },
    ]

    comp_path = project_dir / "benchmarks" / "comparison_with_existing_vpre_blocynfo.csv"
    write_csv(
        comp_path,
        comparison_rows,
        [
            "metric",
            "paper_sensh_sepolia",
            "paper_vpre_sepolia",
            "paper_blocynfo_sepolia",
            "existing_ecc_pre",
        ],
    )

    print(f"Saved detail: {detail_path}")
    print(f"Saved summary: {summary_path}")
    print(f"Saved comparison: {comp_path}")


if __name__ == "__main__":
    main()
