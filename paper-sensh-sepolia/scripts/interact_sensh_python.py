import json
from pathlib import Path

from web3 import Web3

from common import artifact, compile_contracts, compute_label, execute_fn, load_deployment, pick_config


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

    deploy = load_deployment(project_dir)
    compiled = compile_contracts(project_dir)
    se_art = artifact(compiled, "contracts/SENSHSearchableEncryption.sol", "SENSHSearchableEncryption")

    contract = w3.eth.contract(address=deploy["senshSearchableEncryption"], abi=se_art["abi"])

    owner_acct = w3.eth.account.from_key(cfg["private_key"])
    query_pk = cfg["query_private_key"] or cfg["private_key"]
    query_acct = w3.eth.account.from_key(query_pk)

    tx_map = {}
    if query_acct.address != owner_acct.address:
        rcpt = execute_fn(
            w3,
            contract.functions.authorizeUser(query_acct.address),
            cfg["private_key"],
            cfg["chain_id"],
        )
        tx_map["authorizeUser"] = rcpt["transactionHash"].hex()

    key_material = "hospital-master-key"
    endata = "patient:alice:blood-pressure"
    reenc_value = Web3.keccak(text="reencrypted-value-v1")
    label = compute_label(key_material, endata)

    rcpt = execute_fn(
        w3,
        contract.functions.generateLabel(key_material, endata, reenc_value),
        query_pk,
        cfg["chain_id"],
    )
    tx_map["generateLabel"] = rcpt["transactionHash"].hex()

    rcpt = execute_fn(w3, contract.functions.generateToken(label), query_pk, cfg["chain_id"])
    tx_map["generateToken"] = rcpt["transactionHash"].hex()

    results, matched = contract.functions.search(label).call({"from": query_acct.address})
    rcpt = execute_fn(w3, contract.functions.search(label), query_pk, cfg["chain_id"])
    tx_map["search"] = rcpt["transactionHash"].hex()

    new_val = Web3.keccak(text="reencrypted-value-v2")
    rcpt = execute_fn(w3, contract.functions.updateLabel(label, new_val), query_pk, cfg["chain_id"])
    tx_map["updateLabel"] = rcpt["transactionHash"].hex()

    interaction = {
        "contract": deploy["senshSearchableEncryption"],
        "owner": owner_acct.address,
        "queryUser": query_acct.address,
        "label": label.hex(),
        "matchedCiphertext": matched.hex() if isinstance(matched, bytes) else str(matched),
        "obfuscatedResultsCount": len(results),
        "tx": tx_map,
    }

    out_file = project_dir / "data" / "interaction_result.json"
    out_file.write_text(json.dumps(interaction, indent=2), encoding="utf-8")
    print(json.dumps(interaction, indent=2))
    print(f"Saved: {out_file}")


if __name__ == "__main__":
    main()
