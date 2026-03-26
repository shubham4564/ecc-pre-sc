import json
from pathlib import Path

from web3 import Web3

from common import artifact, compile_contracts, pick_config, send_tx


def deploy_contract(w3: Web3, private_key: str, chain_id: int, abi, bytecode: str, args):
    account = w3.eth.account.from_key(private_key)
    nonce = w3.eth.get_transaction_count(account.address)
    c = w3.eth.contract(abi=abi, bytecode=bytecode)

    tx = c.constructor(*args).build_transaction(
        {
            "from": account.address,
            "nonce": nonce,
            "chainId": chain_id,
            "gas": 8_000_000,
            "gasPrice": w3.eth.gas_price,
        }
    )
    rcpt = send_tx(w3, private_key, tx)
    return rcpt["contractAddress"], rcpt


def main() -> None:
    project_dir = Path(__file__).resolve().parents[1]
    cfg = pick_config(project_dir)

    if not cfg["rpc_url"]:
        raise RuntimeError("Missing RPC_URL or ALCHEMY_SEPOLIA_URL")
    if not cfg["private_key"]:
        raise RuntimeError("Missing PRIVATE_KEY or DEPLOYER_PRIVATE_KEY")

    w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
    if not w3.is_connected():
        raise RuntimeError("RPC connection failed")

    compiled = compile_contracts(project_dir)
    acc = artifact(compiled, "contracts/ACCSC.sol", "ACCSC")
    ver = artifact(compiled, "contracts/VERSC.sol", "VERSC")

    deployer = w3.eth.account.from_key(cfg["private_key"])

    acc_addr, r1 = deploy_contract(
        w3,
        cfg["private_key"],
        cfg["chain_id"],
        acc["abi"],
        acc["bytecode"],
        [deployer.address, 100, cfg["attr_count"]],
    )

    phi = Web3.keccak(text="paper-low-latency-phi")
    varphi = Web3.keccak(text="paper-low-latency-varphi")
    ver_addr, r2 = deploy_contract(
        w3,
        cfg["private_key"],
        cfg["chain_id"],
        ver["abi"],
        ver["bytecode"],
        [deployer.address, phi, varphi],
    )

    output = {
        "network": "sepolia",
        "chainId": cfg["chain_id"],
        "deployer": deployer.address,
        "accsc": acc_addr,
        "versc": ver_addr,
        "phi": Web3.to_hex(phi),
        "varphi": Web3.to_hex(varphi),
        "tx": {
            "deployAccsc": r1["transactionHash"].hex(),
            "deployVersc": r2["transactionHash"].hex(),
        },
    }

    out_file = project_dir / "data" / "deployed.sepolia.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print(json.dumps(output, indent=2))
    print(f"Saved: {out_file}")


if __name__ == "__main__":
    main()
