import json
import os
import subprocess
from pathlib import Path
from typing import Dict, Any

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


def pick_config() -> Dict[str, str]:
    here = Path(__file__).resolve()
    project_dir = here.parent.parent
    root_env = project_dir.parent / ".env"
    local_env = project_dir / ".env"

    cfg = {}
    cfg.update(load_env_file(root_env))
    cfg.update(load_env_file(local_env))

    for k, v in os.environ.items():
        cfg[k] = v

    api_key = cfg.get("ALCHEMY_API") or cfg.get("ALCHEMY_API_KEY", "")
    rpc_url = cfg.get("RPC_URL") or cfg.get("ALCHEMY_SEPOLIA_URL")
    if not rpc_url and api_key:
        rpc_url = f"https://eth-sepolia.g.alchemy.com/v2/{api_key}"

    private_key = cfg.get("PRIVATE_KEY") or cfg.get("DEPLOYER_PRIVATE_KEY")
    if private_key and not private_key.startswith("0x"):
        private_key = "0x" + private_key

    deployer = cfg.get("WALLET_ADDRESS") or cfg.get("DEPLOYER_ADDRESS")
    evaluator = cfg.get("EVALUATOR_ADDRESS") or deployer
    chain_id = int(cfg.get("CHAIN_ID", "11155111"))
    trade_window = int(cfg.get("TRADE_WINDOW_SECONDS", "3600"))

    return {
        "rpc_url": rpc_url or "",
        "private_key": private_key or "",
        "deployer": deployer or "",
        "evaluator": evaluator or "",
        "chain_id": chain_id,
        "trade_window": trade_window,
        "project_dir": str(project_dir),
    }


def build_sources(contract_dir: Path) -> Dict[str, Dict[str, str]]:
    sources: Dict[str, Dict[str, str]] = {}
    for p in contract_dir.glob("*.sol"):
        sources[f"contracts/{p.name}"] = {"content": p.read_text(encoding="utf-8")}
    return sources


def compile_contracts(project_dir: Path) -> Dict[str, Any]:
    solc_bin = project_dir / "scripts" / "solc-windows.exe"
    if not solc_bin.exists():
        raise RuntimeError(f"Missing compiler binary: {solc_bin}")

    std_input = {
        "language": "Solidity",
        "sources": build_sources(project_dir / "contracts"),
        "settings": {
            "optimizer": {"enabled": True, "runs": 200},
            "outputSelection": {
                "*": {
                    "*": ["abi", "evm.bytecode.object"]
                }
            },
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

    compiled = json.loads(proc.stdout)
    if "errors" in compiled:
        fatal = [e for e in compiled["errors"] if e.get("severity") == "error"]
        if fatal:
            raise RuntimeError("solc compilation errors:\n" + "\n".join(e.get("formattedMessage", str(e)) for e in fatal))
    return compiled


def get_artifact(compiled: Dict[str, Any], source: str, name: str) -> Dict[str, Any]:
    c = compiled["contracts"][source][name]
    return {"abi": c["abi"], "bytecode": c["evm"]["bytecode"]["object"]}


def send_tx(w3: Web3, private_key: str, tx: Dict[str, Any]) -> Dict[str, Any]:
    signed = w3.eth.account.sign_transaction(tx, private_key=private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return dict(receipt)


def deploy_contract(w3: Web3, private_key: str, chain_id: int, abi, bytecode: str, args, nonce: int):
    account = w3.eth.account.from_key(private_key)
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)

    tx = contract.constructor(*args).build_transaction(
        {
            "from": account.address,
            "nonce": nonce,
            "chainId": chain_id,
            "gas": 8_000_000,
            "gasPrice": w3.eth.gas_price,
        }
    )
    receipt = send_tx(w3, private_key, tx)
    return receipt["contractAddress"], nonce + 1, receipt


def call_contract_tx(w3: Web3, private_key: str, chain_id: int, contract_address: str, abi, fn_name: str, args, nonce: int):
    account = w3.eth.account.from_key(private_key)
    c = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=abi)
    fn = getattr(c.functions, fn_name)(*args)

    tx = fn.build_transaction(
        {
            "from": account.address,
            "nonce": nonce,
            "chainId": chain_id,
            "gas": 500_000,
            "gasPrice": w3.eth.gas_price,
        }
    )
    receipt = send_tx(w3, private_key, tx)
    return nonce + 1, receipt


def main():
    cfg = pick_config()

    if not cfg["rpc_url"]:
        raise RuntimeError("Missing RPC URL. Set RPC_URL or ALCHEMY_SEPOLIA_URL/ALCHEMY_API in .env")
    if not cfg["private_key"]:
        raise RuntimeError("Missing private key. Set PRIVATE_KEY or DEPLOYER_PRIVATE_KEY in .env")

    project_dir = Path(cfg["project_dir"])
    w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
    if not w3.is_connected():
        raise RuntimeError("Failed to connect to RPC endpoint")

    account = w3.eth.account.from_key(cfg["private_key"])
    if cfg["deployer"] and Web3.to_checksum_address(cfg["deployer"]) != account.address:
        raise RuntimeError(f"WALLET_ADDRESS does not match private key. key={account.address}, env={cfg['deployer']}")

    evaluator = Web3.to_checksum_address(cfg["evaluator"] or account.address)

    compiled = compile_contracts(project_dir)

    auth_art = get_artifact(compiled, "contracts/Authentication.sol", "Authentication")
    dl_art = get_artifact(compiled, "contracts/DataList.sol", "DataList")
    ff_art = get_artifact(compiled, "contracts/FundFlow.sol", "FundFlow")
    tr_art = get_artifact(compiled, "contracts/Trading.sol", "Trading")

    nonce = w3.eth.get_transaction_count(account.address)

    auth_addr, nonce, r1 = deploy_contract(
        w3, cfg["private_key"], cfg["chain_id"], auth_art["abi"], auth_art["bytecode"], [account.address, evaluator], nonce
    )
    dl_addr, nonce, r2 = deploy_contract(
        w3, cfg["private_key"], cfg["chain_id"], dl_art["abi"], dl_art["bytecode"], [account.address, auth_addr], nonce
    )
    ff_addr, nonce, r3 = deploy_contract(
        w3, cfg["private_key"], cfg["chain_id"], ff_art["abi"], ff_art["bytecode"], [account.address, dl_addr, cfg["trade_window"]], nonce
    )
    tr_addr, nonce, r4 = deploy_contract(
        w3, cfg["private_key"], cfg["chain_id"], tr_art["abi"], tr_art["bytecode"], [account.address, ff_addr], nonce
    )

    nonce, r5 = call_contract_tx(
        w3, cfg["private_key"], cfg["chain_id"], dl_addr, dl_art["abi"], "setTradingContract", [tr_addr], nonce
    )
    nonce, r6 = call_contract_tx(
        w3, cfg["private_key"], cfg["chain_id"], ff_addr, ff_art["abi"], "setTradingContract", [tr_addr], nonce
    )

    def h(x: str) -> str:
        return x if str(x).startswith("0x") else f"0x{x}"

    result = {
        "network": "sepolia",
        "chainId": cfg["chain_id"],
        "deployer": account.address,
        "evaluator": evaluator,
        "authentication": auth_addr,
        "dataList": dl_addr,
        "fundFlow": ff_addr,
        "trading": tr_addr,
        "tradeWindowSeconds": cfg["trade_window"],
        "tx": {
            "authDeploy": h(r1.get("transactionHash").hex()),
            "dataListDeploy": h(r2.get("transactionHash").hex()),
            "fundFlowDeploy": h(r3.get("transactionHash").hex()),
            "tradingDeploy": h(r4.get("transactionHash").hex()),
            "setTradingOnDataList": h(r5.get("transactionHash").hex()),
            "setTradingOnFundFlow": h(r6.get("transactionHash").hex()),
        },
    }

    out_file = project_dir / "data" / "deployed.sepolia.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(json.dumps(result, indent=2))
    print(f"Saved: {out_file}")


if __name__ == "__main__":
    main()
