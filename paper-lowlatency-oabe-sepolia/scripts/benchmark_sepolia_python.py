import csv
import os
from pathlib import Path
from typing import Dict, List

from web3 import Web3

from common import (
    artifact,
    compile_contracts,
    execute_fn,
    load_deployment,
    now_ms,
    pick_config,
    summary_from_detail,
    write_csv,
)
from offchain_helpers import build_policy_vector, pseudo_mle_encrypt


def read_total_gas(path: Path) -> float | None:
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


def read_total_latency_ms(path: Path) -> float | None:
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

    acc_art = artifact(compiled, "contracts/ACCSC.sol", "ACCSC")
    ver_art = artifact(compiled, "contracts/VERSC.sol", "VERSC")

    acc = w3.eth.contract(address=deploy["accsc"], abi=acc_art["abi"])
    ver = w3.eth.contract(address=deploy["versc"], abi=ver_art["abi"])

    owner_pk = cfg["private_key"]
    user_pk = cfg["user_private_key"] or cfg["private_key"]
    user = w3.eth.account.from_key(user_pk)

    phi = bytes.fromhex(deploy["phi"][2:])
    varphi = bytes.fromhex(deploy["varphi"][2:])

    rows: List[Dict[str, object]] = []

    for i in range(1, iters + 1):
        mtag = Web3.keccak(text=f"lowlatency-mtag-{i}")
        policy = build_policy_vector(cfg["attr_count"], [0, 2, 5])
        message = f"drone:payload:{i}".encode("utf-8")
        sigma = Web3.keccak(text=f"sigma-{i}")
        _, _cmle, r_code, h2m, ctag = pseudo_mle_encrypt(message, sigma, phi, varphi)
        h2r = Web3.keccak(r_code)

        t0 = now_ms()
        rcpt = execute_fn(w3, acc.functions.setTagPolicy(mtag, policy, h2r), owner_pk, cfg["chain_id"])
        t1 = now_ms()
        rows.append({"operation": "setTagPolicy", "iteration": i, "tx_hash": rcpt["transactionHash"].hex(), "gas_used": rcpt["gasUsed"], "latency_ms": t1 - t0})

        t0 = now_ms()
        rcpt = execute_fn(w3, ver.functions.registerCipherMeta(mtag, ctag, h2r), owner_pk, cfg["chain_id"])
        t1 = now_ms()
        rows.append({"operation": "registerCipherMeta", "iteration": i, "tx_hash": rcpt["transactionHash"].hex(), "gas_used": rcpt["gasUsed"], "latency_ms": t1 - t0})

        user_attrs_ok = build_policy_vector(cfg["attr_count"], [0, 2, 5, 7])
        t0 = now_ms()
        rcpt = execute_fn(w3, acc.functions.arrPolicyVerifyCode(mtag, user_attrs_ok, i, user.address), user_pk, cfg["chain_id"])
        t1 = now_ms()
        rows.append({"operation": "arrPolicyVerifyCode", "iteration": i, "tx_hash": rcpt["transactionHash"].hex(), "gas_used": rcpt["gasUsed"], "latency_ms": t1 - t0})

        t0 = now_ms()
        rcpt = execute_fn(w3, ver.functions.conformVerifyTx(mtag, h2m, h2r), user_pk, cfg["chain_id"])
        t1 = now_ms()
        rows.append({"operation": "conformVerifyTx", "iteration": i, "tx_hash": rcpt["transactionHash"].hex(), "gas_used": rcpt["gasUsed"], "latency_ms": t1 - t0})

    detail_path = project_dir / "benchmarks" / "paper_lowlatency_oabe_sepolia_detail.csv"
    summary_path = project_dir / "benchmarks" / "paper_lowlatency_oabe_sepolia_summary.csv"
    comp_path = project_dir / "benchmarks" / "comparison_with_existing_vpre_blocynfo_sensh.csv"

    write_csv(detail_path, rows, ["operation", "iteration", "tx_hash", "gas_used", "latency_ms"])

    summary_rows = summary_from_detail(rows)
    write_csv(
        summary_path,
        summary_rows,
        ["operation", "count", "gas_mean", "gas_min", "gas_max", "latency_ms_mean", "latency_ms_min", "latency_ms_max"],
    )

    total_gas = sum(float(r["gas_mean"]) for r in summary_rows)
    total_latency = sum(float(r["latency_ms_mean"]) for r in summary_rows)

    existing_summary = project_dir.parent / "benchmarks" / "timing_bench.csv"
    vpre_summary = project_dir.parent / "paper-vpre-sepolia" / "benchmarks" / "paper_vpre_sepolia_summary.csv"
    blocynfo_summary = project_dir.parent / "paper-blocynfo-sepolia" / "benchmarks" / "paper_blocynfo_sepolia_summary.csv"
    sensh_summary = project_dir.parent / "paper-sensh-sepolia" / "benchmarks" / "paper_sensh_sepolia_summary.csv"
    prior_comp = project_dir.parent / "paper-blocynfo-sepolia" / "benchmarks" / "comparison_with_existing_and_vpre.csv"

    existing_gas = read_total_gas(existing_summary)
    if existing_gas is None:
        existing_gas = read_existing_from_prior_comparison(prior_comp, "end_to_end_gas")

    existing_latency = read_total_latency_ms(existing_summary)
    prior_latency = read_existing_from_prior_comparison(prior_comp, "end_to_end_latency_ms")
    if prior_latency is not None:
        existing_latency = prior_latency

    comp_rows = [
        {
            "metric": "end_to_end_gas",
            "paper_lowlatency_oabe_sepolia": total_gas,
            "paper_sensh_sepolia": read_total_gas(sensh_summary),
            "paper_vpre_sepolia": read_total_gas(vpre_summary),
            "paper_blocynfo_sepolia": read_total_gas(blocynfo_summary),
            "existing_ecc_pre": existing_gas,
        },
        {
            "metric": "end_to_end_latency_ms",
            "paper_lowlatency_oabe_sepolia": total_latency,
            "paper_sensh_sepolia": read_total_latency_ms(sensh_summary),
            "paper_vpre_sepolia": read_total_latency_ms(vpre_summary),
            "paper_blocynfo_sepolia": read_total_latency_ms(blocynfo_summary),
            "existing_ecc_pre": existing_latency,
        },
    ]

    write_csv(
        comp_path,
        comp_rows,
        [
            "metric",
            "paper_lowlatency_oabe_sepolia",
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
