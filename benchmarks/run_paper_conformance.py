import csv
import json
import os
import subprocess
import sys
from pathlib import Path


def run_check(name: str, cwd: Path, args: list[str]) -> dict:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(args, cwd=str(cwd), capture_output=True, text=True, encoding="utf-8", env=env)
    ok = proc.returncode == 0
    tail_lines = (proc.stdout + "\n" + proc.stderr).strip().splitlines()[-20:]
    return {
        "check": name,
        "status": "pass" if ok else "fail",
        "exit_code": proc.returncode,
        "output_tail": "\n".join(tail_lines),
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    py = sys.executable

    # All six implementations are tested at the same level:
    # each runs a Sepolia-based conformance script that deploys to (or uses the
    # already-deployed contract on) Sepolia and exercises the core protocol workflow.
    # This is apple-to-apple: every implementation hits a real EVM node with real
    # transactions, using the same .env credentials.
    checks = [
        {
            "name": "existing_ecc_pre_conformance",
            "cwd": root,
            "args": [py, "scripts/conformance_sepolia.py"],
        },
        {
            "name": "vpre_sepolia_conformance",
            "cwd": root / "paper-vpre-sepolia",
            "args": [py, "scripts/conformance_sepolia.py"],
        },
        {
            "name": "sensh_sepolia_conformance",
            "cwd": root / "paper-sensh-sepolia",
            "args": [py, "scripts/conformance_sepolia.py"],
        },
        {
            "name": "blocynfo_sepolia_conformance",
            "cwd": root / "paper-blocynfo-sepolia",
            "args": [py, "scripts/conformance_sepolia.py"],
        },
        {
            "name": "lowlatency_sepolia_conformance",
            "cwd": root / "paper-lowlatency-oabe-sepolia",
            "args": [py, "scripts/conformance_sepolia.py"],
        },
        {
            "name": "anon_iot_pre_sepolia_conformance",
            "cwd": root / "paper-anon-iot-pre-sepolia",
            "args": [py, "scripts/conformance_sepolia.py"],
        },
    ]

    rows = [run_check(c["name"], c["cwd"], c["args"]) for c in checks]

    all_pass = all(r["status"] == "pass" for r in rows)
    summary = {
        "overall_status": "pass" if all_pass else "fail",
        "checks": rows,
    }

    out_json = root / "benchmarks" / "paper_methodology_conformance.json"
    out_csv = root / "benchmarks" / "paper_methodology_conformance.csv"

    out_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["check", "status", "exit_code", "output_tail"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"overall_status={summary['overall_status']}")
    print(f"saved_json={out_json}")
    print(f"saved_csv={out_csv}")

    if not all_pass:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
