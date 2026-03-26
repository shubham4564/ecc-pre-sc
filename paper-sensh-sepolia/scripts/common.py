import csv
import json
import os
import subprocess
import time
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, List

from web3 import Web3


def load_env_file(path: Path) -> Dict[str, str]:
    env: Dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def pick_config(project_dir: Path) -> Dict[str, Any]:
    root_env = project_dir.parent / ".env"
    local_env = project_dir / ".env"

    cfg: Dict[str, str] = {}
    cfg.update(load_env_file(root_env))
    cfg.update(load_env_file(local_env))
    cfg.update({k: v for k, v in os.environ.items()})

    rpc_url = cfg.get("RPC_URL") or cfg.get("ALCHEMY_SEPOLIA_URL")
    api_key = cfg.get("ALCHEMY_API") or cfg.get("ALCHEMY_API_KEY", "")
    if not rpc_url and api_key:
        rpc_url = f"https://eth-sepolia.g.alchemy.com/v2/{api_key}"

    private_key = cfg.get("PRIVATE_KEY") or cfg.get("DEPLOYER_PRIVATE_KEY", "")
    query_private_key = cfg.get("QUERY_PRIVATE_KEY", "")

    if private_key and not private_key.startswith("0x"):
        private_key = "0x" + private_key
    if query_private_key and not query_private_key.startswith("0x"):
        query_private_key = "0x" + query_private_key

    return {
        "rpc_url": rpc_url or "",
        "private_key": private_key,
        "query_private_key": query_private_key,
        "chain_id": int(cfg.get("CHAIN_ID", "11155111")),
        "bf_bits": int(cfg.get("BF_BITS", "4096")),
        "bf_hashes": int(cfg.get("BF_HASHES", "3")),
    }


def find_solc_binary(project_dir: Path) -> Path:
    candidates = [
        project_dir / "scripts" / "solc-windows.exe",
        project_dir.parent / "paper-vpre-sepolia" / "scripts" / "solc-windows.exe",
    ]
    for path in candidates:
        if path.exists():
            return path
    raise RuntimeError("Missing solc-windows.exe in paper-sensh-sepolia/scripts/ or paper-vpre-sepolia/scripts/")


def compile_contracts(project_dir: Path) -> Dict[str, Any]:
    solc = find_solc_binary(project_dir)
    sources: Dict[str, Dict[str, str]] = {}

    for p in (project_dir / "contracts").glob("*.sol"):
        key = f"contracts/{p.name}"
        sources[key] = {"content": p.read_text(encoding="utf-8")}

    std_input = {
        "language": "Solidity",
        "sources": sources,
        "settings": {
            "optimizer": {"enabled": True, "runs": 200},
            "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object"]}},
        },
    }

    proc = subprocess.run(
        [str(solc), "--standard-json"],
        input=json.dumps(std_input),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"solc failed: {proc.stderr}")

    out = json.loads(proc.stdout)
    fatal = [e for e in out.get("errors", []) if e.get("severity") == "error"]
    if fatal:
        msgs = "\n".join(e.get("formattedMessage", str(e)) for e in fatal)
        raise RuntimeError(f"solc errors:\n{msgs}")

    return out


def artifact(compiled: Dict[str, Any], source: str, name: str) -> Dict[str, Any]:
    obj = compiled["contracts"][source][name]
    return {
        "abi": obj["abi"],
        "bytecode": obj["evm"]["bytecode"]["object"],
    }


def send_tx(w3: Web3, private_key: str, tx: Dict[str, Any]) -> Dict[str, Any]:
    signed = w3.eth.account.sign_transaction(tx, private_key=private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return dict(receipt)


def execute_fn(w3: Web3, fn, private_key: str, chain_id: int) -> Dict[str, Any]:
    account = w3.eth.account.from_key(private_key)
    nonce = w3.eth.get_transaction_count(account.address, "pending")
    tx = fn.build_transaction(
        {
            "from": account.address,
            "nonce": nonce,
            "chainId": chain_id,
            "gas": 8_000_000,
            "gasPrice": w3.eth.gas_price,
        }
    )
    return send_tx(w3, private_key, tx)


def load_deployment(project_dir: Path) -> Dict[str, Any]:
    p = project_dir / "data" / "deployed.sepolia.json"
    if not p.exists():
        raise RuntimeError(f"Missing deployment file: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def compute_label(key_material: str, endata: str) -> bytes:
    k1 = Web3.solidity_keccak(["string", "string"], [key_material, "k1"])
    return Web3.solidity_keccak(["bytes32", "string"], [k1, endata])


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def summary_from_detail(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["operation"]), []).append(row)

    summary: List[Dict[str, Any]] = []
    for op, items in grouped.items():
        gas_vals = [int(i["gas_used"]) for i in items]
        latency_vals = [float(i["latency_ms"]) for i in items]
        summary.append(
            {
                "operation": op,
                "count": len(items),
                "gas_mean": mean(gas_vals),
                "gas_min": min(gas_vals),
                "gas_max": max(gas_vals),
                "latency_ms_mean": mean(latency_vals),
                "latency_ms_min": min(latency_vals),
                "latency_ms_max": max(latency_vals),
            }
        )
    return summary


def now_ms() -> float:
    return time.perf_counter() * 1000.0
