import json
from pathlib import Path

from web3 import Web3

from deploy_sepolia_python import pick_config, compile_contracts, get_artifact
from offchain_utils import key_gen, compute_rk, compute_vk


def load_deployed(project_dir: Path):
    p = project_dir / "data" / "deployed.sepolia.json"
    if not p.exists():
        raise RuntimeError(f"Missing deployed file: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def send_tx(w3: Web3, private_key: str, tx):
    signed = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return dict(w3.eth.wait_for_transaction_receipt(tx_hash))


def main():
    cfg = pick_config()
    project_dir = Path(cfg["project_dir"])
    deployed = load_deployed(project_dir)

    w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
    if not w3.is_connected():
        raise RuntimeError("RPC connection failed")

    compiled = compile_contracts(project_dir)
    auth_abi = get_artifact(compiled, "contracts/Authentication.sol", "Authentication")["abi"]
    dl_abi = get_artifact(compiled, "contracts/DataList.sol", "DataList")["abi"]
    ff_abi = get_artifact(compiled, "contracts/FundFlow.sol", "FundFlow")["abi"]
    tr_abi = get_artifact(compiled, "contracts/Trading.sol", "Trading")["abi"]

    auth = w3.eth.contract(address=Web3.to_checksum_address(deployed["authentication"]), abi=auth_abi)
    dl = w3.eth.contract(address=Web3.to_checksum_address(deployed["dataList"]), abi=dl_abi)
    ff = w3.eth.contract(address=Web3.to_checksum_address(deployed["fundFlow"]), abi=ff_abi)
    tr = w3.eth.contract(address=Web3.to_checksum_address(deployed["trading"]), abi=tr_abi)

    account = w3.eth.account.from_key(cfg["private_key"])
    nonce = w3.eth.get_transaction_count(account.address)
    gas_price = w3.eth.gas_price

    ds = key_gen()
    db = key_gen()
    sk_e = key_gen()["sk"]

    submission_id = Web3.to_hex(Web3.solidity_keccak(["address", "uint256"], [account.address, nonce]))
    dd_hash = Web3.to_hex(Web3.solidity_keccak(["string"], ["sample-dd"]))

    tx = auth.functions.submitForAuthentication(submission_id, ds["pk"], b"Cfk", dd_hash).build_transaction(
        {"from": account.address, "nonce": nonce, "gas": 500_000, "gasPrice": gas_price, "chainId": cfg["chain_id"]}
    )
    rcpt = send_tx(w3, cfg["private_key"], tx)
    print("submitForAuthentication:", Web3.to_hex(rcpt["transactionHash"]))
    nonce += 1

    tx = auth.functions.authenticateData(submission_id, b"Ckey", "ipfs://sample").build_transaction(
        {"from": account.address, "nonce": nonce, "gas": 700_000, "gasPrice": gas_price, "chainId": cfg["chain_id"]}
    )
    rcpt = send_tx(w3, cfg["private_key"], tx)
    print("authenticateData:", Web3.to_hex(rcpt["transactionHash"]))
    nonce += 1

    evt = auth.events.ProductAuthenticated().process_receipt(rcpt)
    uid = int(evt[0]["args"]["uid"])

    tx = dl.functions.listData(uid, 1).build_transaction(
        {"from": account.address, "nonce": nonce, "gas": 300_000, "gasPrice": gas_price, "chainId": cfg["chain_id"]}
    )
    rcpt = send_tx(w3, cfg["private_key"], tx)
    print("listData:", Web3.to_hex(rcpt["transactionHash"]))
    nonce += 1

    tx = ff.functions.deposit(uid).build_transaction(
        {"from": account.address, "nonce": nonce, "gas": 400_000, "gasPrice": gas_price, "chainId": cfg["chain_id"], "value": 1}
    )
    rcpt = send_tx(w3, cfg["private_key"], tx)
    print("deposit:", Web3.to_hex(rcpt["transactionHash"]))
    nonce += 1

    rk_out = compute_rk(ds["sk"], db["pk"], sk_e)
    vk_out = compute_vk(ds["pk"], db["pk"], db["sk"], rk_out["pk_e"])

    tx = tr.functions.submitCmit(uid, ds["pk"], db["pk"], rk_out["pk_e"], rk_out["cmit"]).build_transaction(
        {"from": account.address, "nonce": nonce, "gas": 350_000, "gasPrice": gas_price, "chainId": cfg["chain_id"]}
    )
    rcpt = send_tx(w3, cfg["private_key"], tx)
    print("submitCmit:", Web3.to_hex(rcpt["transactionHash"]))
    nonce += 1

    tx = tr.functions.submitVK(uid, vk_out["vk"]).build_transaction(
        {"from": account.address, "nonce": nonce, "gas": 350_000, "gasPrice": gas_price, "chainId": cfg["chain_id"]}
    )
    rcpt = send_tx(w3, cfg["private_key"], tx)
    print("submitVK:", Web3.to_hex(rcpt["transactionHash"]))
    nonce += 1

    tx = tr.functions.settlement(uid, rk_out["rk"]).build_transaction(
        {"from": account.address, "nonce": nonce, "gas": 1_000_000, "gasPrice": gas_price, "chainId": cfg["chain_id"]}
    )
    rcpt = send_tx(w3, cfg["private_key"], tx)
    print("settlement:", Web3.to_hex(rcpt["transactionHash"]))


if __name__ == "__main__":
    main()
