import json
from pathlib import Path

from web3 import Web3

from common import artifact, compile_contracts, pick_config, send_tx


def deploy_contract(w3: Web3, private_key: str, chain_id: int, abi, bytecode: str, args):
    account = w3.eth.account.from_key(private_key)
    nonce = w3.eth.get_transaction_count(account.address)
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)

    tx = contract.constructor(*args).build_transaction(
        {
            "from": account.address,
            "nonce": nonce,
            "chainId": chain_id,
            "gas": 9_000_000,
            "gasPrice": w3.eth.gas_price,
        }
    )
    receipt = send_tx(w3, private_key, tx)
    return receipt["contractAddress"], receipt


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
    se = artifact(compiled, "contracts/SENSHSearchableEncryption.sol", "SENSHSearchableEncryption")

    deployer = w3.eth.account.from_key(cfg["private_key"])
    se_addr, rcpt = deploy_contract(
        w3,
        cfg["private_key"],
        cfg["chain_id"],
        se["abi"],
        se["bytecode"],
        [deployer.address, cfg["bf_bits"], cfg["bf_hashes"]],
    )

    se_contract = w3.eth.contract(address=se_addr, abi=se["abi"])
    labels_filter = se_contract.functions.labelsFilter().call()
    users_filter = se_contract.functions.authorizedUsersFilter().call()

    output = {
        "network": "sepolia",
        "chainId": cfg["chain_id"],
        "deployer": deployer.address,
        "senshSearchableEncryption": se_addr,
        "labelsFilter": labels_filter,
        "authorizedUsersFilter": users_filter,
        "tx": {"deploy": rcpt["transactionHash"].hex()},
    }

    out_file = project_dir / "data" / "deployed.sepolia.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print(json.dumps(output, indent=2))
    print(f"Saved: {out_file}")


if __name__ == "__main__":
    main()
