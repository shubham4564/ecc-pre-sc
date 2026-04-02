import json
from pathlib import Path

from web3 import Web3

from common import artifact, compile_contracts, execute_fn, load_deployment, pick_config
from offchain_helpers import derive_rekey_commitment, derive_transformed_cipher_hash, pseudonym, stable_cipher_hash


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
    art = artifact(compiled, "contracts/IoTAnonymousPRE.sol", "IoTAnonymousPRE")

    c = w3.eth.contract(address=deploy["iotAnonymousPre"], abi=art["abi"])

    owner_pk = cfg["private_key"]
    owner = w3.eth.account.from_key(owner_pk)

    device_pk = cfg["query_private_key"] or owner_pk
    device = w3.eth.account.from_key(device_pk)

    owner_pseudo = pseudonym(f"owner:{owner.address}")
    device_pseudo = pseudonym(f"device:{device.address}")

    tx_map = {}

    rcpt = execute_fn(w3, c.functions.registerOwner(owner_pseudo), owner_pk, cfg["chain_id"])
    tx_map["registerOwner"] = rcpt["transactionHash"].hex()

    rcpt = execute_fn(
        w3,
        c.functions.registerDevice(owner_pseudo, device_pseudo, device.address),
        owner_pk,
        cfg["chain_id"],
    )
    tx_map["registerDevice"] = rcpt["transactionHash"].hex()

    cipher_hash = stable_cipher_hash(b"iot-sample-ciphertext")
    policy_hash = Web3.keccak(text="attr:temperature|region:ward-a")

    rcpt = execute_fn(w3, c.functions.authorizeData(device_pseudo, cipher_hash, policy_hash), owner_pk, cfg["chain_id"])
    tx_map["authorizeData"] = rcpt["transactionHash"].hex()

    data_id = Web3.solidity_keccak(["bytes32", "bytes32", "bytes32", "bytes32"], [owner_pseudo, device_pseudo, cipher_hash, policy_hash])

    rekey_commit = derive_rekey_commitment(owner_pk, data_id)
    rcpt = execute_fn(w3, c.functions.submitReKey(data_id, rekey_commit), owner_pk, cfg["chain_id"])
    tx_map["submitReKey"] = rcpt["transactionHash"].hex()

    request_nonce = Web3.keccak(text="req-1")
    rcpt = execute_fn(w3, c.functions.requestReEncryption(data_id, request_nonce), device_pk, cfg["chain_id"])
    tx_map["requestReEncryption"] = rcpt["transactionHash"].hex()

    request_id = Web3.solidity_keccak(["bytes32", "address", "bytes32"], [data_id, device.address, request_nonce])

    transformed_hash = derive_transformed_cipher_hash(cipher_hash, rekey_commit, request_nonce)
    rcpt = execute_fn(w3, c.functions.approveReEncryption(request_id, transformed_hash), owner_pk, cfg["chain_id"])
    tx_map["approveReEncryption"] = rcpt["transactionHash"].hex()

    ok = c.functions.verifyAccess(request_id, transformed_hash).call({"from": device.address})

    out = {
        "contract": deploy["iotAnonymousPre"],
        "owner": owner.address,
        "device": device.address,
        "ownerPseudo": owner_pseudo.hex(),
        "devicePseudo": device_pseudo.hex(),
        "dataId": data_id.hex(),
        "requestId": request_id.hex(),
        "verifyAccess": bool(ok),
        "tx": tx_map,
    }

    out_path = project_dir / "data" / "interaction_result.json"
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print(json.dumps(out, indent=2))
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
