import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict

from web3 import Web3


def load_env_file(path: Path) -> Dict[str, str]:
    env = {}
    if not path.exists():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def pick_config() -> Dict[str, Any]:
    here = Path(__file__).resolve()
    project_dir = here.parent.parent
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
    if private_key and not private_key.startswith("0x"):
        private_key = "0x" + private_key

    chain_id = int(cfg.get("CHAIN_ID", "11155111"))

    return {
        "project_dir": str(project_dir),
        "rpc_url": rpc_url or "",
        "private_key": private_key,
        "chain_id": chain_id,
    }


def find_solc_binary(project_dir: Path) -> Path:
    candidates = [
        project_dir / "scripts" / "solc-windows.exe",
        project_dir.parent / "paper-vpre-sepolia" / "scripts" / "solc-windows.exe",
    ]
    for c in candidates:
        if c.exists():
            return c
    raise RuntimeError("Missing solc-windows.exe. Put it in paper-blocynfo-sepolia/scripts/ or paper-vpre-sepolia/scripts/.")


def compile_contracts(project_dir: Path) -> Dict[str, Any]:
    solc_bin = find_solc_binary(project_dir)

    sources = {}
    for p in (project_dir / "contracts").glob("*.sol"):
        sources[f"contracts/{p.name}"] = {"content": p.read_text(encoding="utf-8")}

    std_input = {
        "language": "Solidity",
        "sources": sources,
        "settings": {
            "optimizer": {"enabled": True, "runs": 200},
            "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object"]}},
        },
    }

    proc = subprocess.run(
        [str(solc_bin), "--standard-json"],
        input=json.dumps(std_input),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"solc failed: {proc.stderr}")

    out = json.loads(proc.stdout)
    if "errors" in out:
        fatal = [e for e in out["errors"] if e.get("severity") == "error"]
        if fatal:
            raise RuntimeError("solc errors:\n" + "\n".join(e.get("formattedMessage", str(e)) for e in fatal))
    return out


def artifact(compiled: Dict[str, Any], source: str, name: str) -> Dict[str, Any]:
    c = compiled["contracts"][source][name]
    return {"abi": c["abi"], "bytecode": c["evm"]["bytecode"]["object"]}


def send_tx(w3: Web3, private_key: str, tx: Dict[str, Any]) -> Dict[str, Any]:
    signed = w3.eth.account.sign_transaction(tx, private_key=private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return dict(w3.eth.wait_for_transaction_receipt(tx_hash))


def deploy_contract(w3: Web3, private_key: str, chain_id: int, abi, bytecode: str, args, nonce: int):
    account = w3.eth.account.from_key(private_key)
    c = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = c.constructor(*args).build_transaction(
        {
            "from": account.address,
            "nonce": nonce,
            "chainId": chain_id,
            "gas": 7_000_000,
            "gasPrice": w3.eth.gas_price,
        }
    )
    rcpt = send_tx(w3, private_key, tx)
    return rcpt["contractAddress"], nonce + 1, rcpt


def main() -> None:
    cfg = pick_config()
    if not cfg["rpc_url"]:
        raise RuntimeError("Missing RPC_URL or ALCHEMY_SEPOLIA_URL")
    if not cfg["private_key"]:
        raise RuntimeError("Missing PRIVATE_KEY or DEPLOYER_PRIVATE_KEY")

    project_dir = Path(cfg["project_dir"])

    w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
    if not w3.is_connected():
        raise RuntimeError("RPC connection failed")

    compiled = compile_contracts(project_dir)
    art = artifact(compiled, "contracts/BloCyNfoShare.sol", "BloCyNfoShare")

    account = w3.eth.account.from_key(cfg["private_key"])
    nonce = w3.eth.get_transaction_count(account.address)

    addr, nonce, r1 = deploy_contract(w3, cfg["private_key"], cfg["chain_id"], art["abi"], art["bytecode"], [account.address], nonce)

    result = {
        "network": "sepolia",
        "chainId": cfg["chain_id"],
        "deployer": account.address,
        "bloCyNfoShare": addr,
        "tx": {"deploy": r1["transactionHash"].hex()},
    }

    out_file = project_dir / "data" / "deployed.sepolia.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(json.dumps(result, indent=2))
    print(f"Saved: {out_file}")


if __name__ == "__main__":
    main()
