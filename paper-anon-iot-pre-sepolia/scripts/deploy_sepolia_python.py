import json
from pathlib import Path

from web3 import Web3

from common import artifact, compile_contracts, pick_config, send_tx


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
    art = artifact(compiled, "contracts/IoTAnonymousPRE.sol", "IoTAnonymousPRE")

    acct = w3.eth.account.from_key(cfg["private_key"])
    contract = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])

    tx = contract.constructor().build_transaction(
        {
            "from": acct.address,
            "nonce": w3.eth.get_transaction_count(acct.address),
            "gas": 8_000_000,
            "gasPrice": w3.eth.gas_price,
            "chainId": cfg["chain_id"],
        }
    )

    rcpt = send_tx(w3, cfg["private_key"], tx)

    out = {
        "network": "sepolia",
        "chainId": cfg["chain_id"],
        "deployer": acct.address,
        "iotAnonymousPre": rcpt["contractAddress"],
        "deployTxHash": rcpt["transactionHash"].hex(),
        "deployGasUsed": int(rcpt["gasUsed"]),
    }

    out_path = project_dir / "data" / "deployed.sepolia.json"
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print(json.dumps(out, indent=2))
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
