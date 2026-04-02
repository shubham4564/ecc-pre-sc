import json
import os
from pathlib import Path

from web3 import Web3

from deploy_sepolia_python import pick_config, compile_contracts, artifact
from offchain_helpers import canonical_attr_hash, policy_hash, cti_hash, derive_rekey_hash, derive_rekey_blob


def load_deployed(project_dir: Path):
    p = project_dir / "data" / "deployed.sepolia.json"
    if not p.exists():
        raise RuntimeError(f"Missing deployed file: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def send_tx(w3: Web3, pk: str, tx):
    signed = w3.eth.account.sign_transaction(tx, pk)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return dict(w3.eth.wait_for_transaction_receipt(tx_hash))


def main() -> None:
    cfg = pick_config()
    project_dir = Path(cfg["project_dir"])
    deployed = load_deployed(project_dir)

    w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
    if not w3.is_connected():
        raise RuntimeError("RPC connection failed")

    compiled = compile_contracts(project_dir)
    abi = artifact(compiled, "contracts/BloCyNfoShare.sol", "BloCyNfoShare")["abi"]

    c = w3.eth.contract(address=Web3.to_checksum_address(deployed["bloCyNfoShare"]), abi=abi)

    owner_pk = cfg["private_key"]
    owner = w3.eth.account.from_key(owner_pk)

    query_pk = os.environ.get("QUERY_PRIVATE_KEY", "")
    if query_pk and not query_pk.startswith("0x"):
        query_pk = "0x" + query_pk
    if query_pk:
        query = w3.eth.account.from_key(query_pk)
    else:
        query = owner
        query_pk = owner_pk

    nonce_owner = w3.eth.get_transaction_count(owner.address)
    nonce_query = w3.eth.get_transaction_count(query.address)
    gp = w3.eth.gas_price

    params_hash = Web3.keccak(text="blocynfo-params-v1")
    tx = c.functions.storeParams(params_hash, "ipfs://blocynfo/params/v1").build_transaction(
        {"from": owner.address, "nonce": nonce_owner, "gas": 250000, "gasPrice": gp, "chainId": cfg["chain_id"]}
    )
    rcpt = send_tx(w3, owner_pk, tx)
    print("storeParams:", rcpt["transactionHash"].hex())
    nonce_owner += 1

    owner_attrs_hash = canonical_attr_hash(["security manager", "health", "us"])
    tx = c.functions.orgRegistration(
        Web3.keccak(text=f"ORG:{owner.address}"),
        int.from_bytes(Web3.keccak(text="owner-pk"), "big"),
        Web3.keccak(text="owner-creds"),
        owner_attrs_hash,
    ).build_transaction({"from": owner.address, "nonce": nonce_owner, "gas": 350000, "gasPrice": gp, "chainId": cfg["chain_id"]})
    rcpt = send_tx(w3, owner_pk, tx)
    print("orgRegistration(owner):", rcpt["transactionHash"].hex())
    nonce_owner += 1

    if query.address != owner.address:
        query_attrs_hash = canonical_attr_hash(["security manager", "health", "us"])
        tx = c.functions.orgRegistration(
            Web3.keccak(text=f"ORG:{query.address}"),
            int.from_bytes(Web3.keccak(text="query-pk"), "big"),
            Web3.keccak(text="query-creds"),
            query_attrs_hash,
        ).build_transaction({"from": query.address, "nonce": nonce_query, "gas": 350000, "gasPrice": gp, "chainId": cfg["chain_id"]})
        rcpt = send_tx(w3, query_pk, tx)
        print("orgRegistration(query):", rcpt["transactionHash"].hex())
        nonce_query += 1

    tx = c.functions.approveOrganization(owner.address, True, False).build_transaction(
        {"from": owner.address, "nonce": nonce_owner, "gas": 120000, "gasPrice": gp, "chainId": cfg["chain_id"]}
    )
    rcpt = send_tx(w3, owner_pk, tx)
    print("approveOrganization(owner):", rcpt["transactionHash"].hex())
    nonce_owner += 1

    tx = c.functions.approveOrganization(query.address, True, True).build_transaction(
        {"from": owner.address, "nonce": nonce_owner, "gas": 120000, "gasPrice": gp, "chainId": cfg["chain_id"]}
    )
    rcpt = send_tx(w3, owner_pk, tx)
    print("approveOrganization(query):", rcpt["transactionHash"].hex())
    nonce_owner += 1

    query_pub_key = int.from_bytes(Web3.keccak(text="query-pub"), "big")
    tx = c.functions.regPubKey(query_pub_key, Web3.keccak(text="signed-query-pub")).build_transaction(
        {"from": query.address, "nonce": nonce_query, "gas": 180000, "gasPrice": gp, "chainId": cfg["chain_id"]}
    )
    rcpt = send_tx(w3, query_pk, tx)
    print("regPubKey(query):", rcpt["transactionHash"].hex())
    nonce_query += 1

    cti_id = Web3.keccak(text=f"cti:{owner.address}:1")
    policy = {"op": "AND", "children": ["security manager", "health", "us"]}
    p_hash = policy_hash(policy)
    cti_blob = b"encrypted-cti-placeholder"
    c_hash = cti_hash(cti_blob)

    tx = c.functions.hashCTI(cti_id, c_hash, p_hash, "ipfs://blocynfo/cti/1").build_transaction(
        {"from": owner.address, "nonce": nonce_owner, "gas": 250000, "gasPrice": gp, "chainId": cfg["chain_id"]}
    )
    rcpt = send_tx(w3, owner_pk, tx)
    print("hashCTI:", rcpt["transactionHash"].hex())
    nonce_owner += 1

    cti_id_hex = Web3.to_hex(cti_id)
    rk_hash = derive_rekey_hash(owner_pk, query_pub_key, p_hash, cti_id_hex, query.address)
    rk_blob = derive_rekey_blob(owner_pk, query_pub_key, p_hash, cti_id_hex, query.address)

    tx = c.functions.storeReKey(cti_id, query.address, rk_hash, rk_blob).build_transaction(
        {"from": owner.address, "nonce": nonce_owner, "gas": 300000, "gasPrice": gp, "chainId": cfg["chain_id"]}
    )
    rcpt = send_tx(w3, owner_pk, tx)
    print("storeReKey:", rcpt["transactionHash"].hex())
    nonce_owner += 1

    ok = c.functions.verify(cti_id, query.address, c_hash, rk_hash).call()
    print("verify result:", ok)


if __name__ == "__main__":
    main()
