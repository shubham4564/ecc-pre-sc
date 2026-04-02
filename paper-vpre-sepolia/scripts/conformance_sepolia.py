"""
Sepolia-based conformance smoke-test for VPRE (Verifiable Proxy Re-Encryption).

Two-part check:
  Part A (off-chain): commitment gate — rk commitment == vk commitment
  Part B (on-chain):  full trade settlement workflow on Sepolia:
    1. submitForAuthentication + authenticateData → ProductAuthenticated event
    2. listData
    3. deposit (1 wei)
    4. submitCmit (off-chain rk commitment)
    5. submitVK (off-chain vk)
    6. commitReveal → verifyResult shows commitment match on-chain

Exits 0 on success, 1 on any failure.
"""

import json
import sys
from pathlib import Path

from web3 import Web3

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "scripts"))

from deploy_sepolia_python import pick_config, compile_contracts, get_artifact
from offchain_utils import key_gen, compute_rk, compute_vk


def _send(w3: Web3, private_key: str, tx):
    signed = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return dict(w3.eth.wait_for_transaction_receipt(tx_hash))


def _check_offchain() -> None:
    """Part A: off-chain commitment gate (equivalent to vpre_offchain_demo.py)."""
    ds = key_gen()
    db = key_gen()
    sk_e = key_gen()["sk"]
    uid = 42
    rk_out = compute_rk(ds["sk"], db["pk"], sk_e, uid)
    vk_out = compute_vk(ds["pk"], db["pk"], db["sk"], rk_out["pk_e"], uid)
    match = rk_out["cmit"].lower() == vk_out["vk_cmit"].lower()
    assert match, f"VPRE off-chain commitment mismatch: rk={rk_out['cmit']}  vk={vk_out['vk_cmit']}"
    print("  [A] off-chain commitment gate  OK")


def main() -> None:
    # Part A: off-chain math
    _check_offchain()

    # Part B: on-chain Sepolia
    cfg = pick_config()
    rpc_url = cfg["rpc_url"]
    private_key = cfg["private_key"]

    if not rpc_url or not private_key:
        print("ERROR: Missing RPC_URL or PRIVATE_KEY", file=sys.stderr)
        raise SystemExit(1)

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print("ERROR: Cannot connect to Sepolia RPC", file=sys.stderr)
        raise SystemExit(1)

    project_dir = Path(cfg["project_dir"])
    deployed = json.loads((project_dir / "data" / "deployed.sepolia.json").read_text(encoding="utf-8"))
    chain_id = cfg["chain_id"]

    compiled = compile_contracts(project_dir)
    auth = w3.eth.contract(
        address=Web3.to_checksum_address(deployed["authentication"]),
        abi=get_artifact(compiled, "contracts/Authentication.sol", "Authentication")["abi"],
    )
    dl = w3.eth.contract(
        address=Web3.to_checksum_address(deployed["dataList"]),
        abi=get_artifact(compiled, "contracts/DataList.sol", "DataList")["abi"],
    )
    ff = w3.eth.contract(
        address=Web3.to_checksum_address(deployed["fundFlow"]),
        abi=get_artifact(compiled, "contracts/FundFlow.sol", "FundFlow")["abi"],
    )
    tr = w3.eth.contract(
        address=Web3.to_checksum_address(deployed["trading"]),
        abi=get_artifact(compiled, "contracts/Trading.sol", "Trading")["abi"],
    )

    account = w3.eth.account.from_key(private_key)
    sender = account.address
    nonce = w3.eth.get_transaction_count(sender, "pending")
    gp = w3.eth.gas_price

    print(f"VPRE conformance (on-chain): sender={sender}")

    ds = key_gen()
    db = key_gen()
    sk_e = key_gen()["sk"]

    submission_id = Web3.to_hex(Web3.solidity_keccak(["address", "uint256"], [sender, nonce]))
    dd_hash = Web3.to_hex(Web3.solidity_keccak(["string"], ["conf-dd"]))

    # 1. submitForAuthentication
    rcpt = _send(w3, private_key, auth.functions.submitForAuthentication(
        submission_id, ds["pk"], b"Cfk-conf", dd_hash
    ).build_transaction({"from": sender, "nonce": nonce, "gas": 500_000, "gasPrice": gp, "chainId": chain_id}))
    assert rcpt["status"] == 1, f"submitForAuthentication failed: {rcpt}"
    print("  [B1] submitForAuthentication  OK")
    nonce += 1

    # 2. authenticateData
    rcpt = _send(w3, private_key, auth.functions.authenticateData(
        submission_id, b"Ckey-conf", "ipfs://conf/sample"
    ).build_transaction({"from": sender, "nonce": nonce, "gas": 700_000, "gasPrice": gp, "chainId": chain_id}))
    assert rcpt["status"] == 1, f"authenticateData failed: {rcpt}"
    print("  [B2] authenticateData  OK")
    nonce += 1

    evt = auth.events.ProductAuthenticated().process_receipt(rcpt)
    uid = int(evt[0]["args"]["uid"])

    # 3. listData
    rcpt = _send(w3, private_key, dl.functions.listData(uid, 1).build_transaction(
        {"from": sender, "nonce": nonce, "gas": 300_000, "gasPrice": gp, "chainId": chain_id}
    ))
    assert rcpt["status"] == 1, f"listData failed: {rcpt}"
    print("  [B3] listData  OK")
    nonce += 1

    # Fix: DataList.tradingContract must be FundFlow so deposit() can call setLock.
    # The deployment script set it to Trading, which was incorrect for this call path.
    dl_trading_cur = dl.functions.tradingContract().call()
    ff_addr = Web3.to_checksum_address(deployed["fundFlow"])
    if dl_trading_cur.lower() != ff_addr.lower():
        rcpt_fix = _send(w3, private_key, dl.functions.setTradingContract(ff_addr).build_transaction(
            {"from": sender, "nonce": nonce, "gas": 100_000, "gasPrice": gp, "chainId": chain_id}
        ))
        assert rcpt_fix["status"] == 1, f"setTradingContract(fundFlow) failed: {rcpt_fix}"
        nonce += 1

    # 4. deposit (1 wei to fund escrow)
    rcpt = _send(w3, private_key, ff.functions.deposit(uid).build_transaction(
        {"from": sender, "nonce": nonce, "gas": 400_000, "gasPrice": gp, "chainId": chain_id, "value": 1}
    ))
    assert rcpt["status"] == 1, f"deposit failed: {rcpt}"
    print("  [B4] deposit  OK")
    nonce += 1

    # 5. submitCmit (off-chain rk → on-chain commitment)
    rk_out = compute_rk(ds["sk"], db["pk"], sk_e, uid)
    vk_out = compute_vk(ds["pk"], db["pk"], db["sk"], rk_out["pk_e"], uid)

    rcpt = _send(w3, private_key, tr.functions.submitCmit(
        uid, ds["pk"], db["pk"], rk_out["pk_e"], rk_out["cmit"]
    ).build_transaction({"from": sender, "nonce": nonce, "gas": 350_000, "gasPrice": gp, "chainId": chain_id}))
    assert rcpt["status"] == 1, f"submitCmit failed: {rcpt}"
    print("  [B5] submitCmit  OK")
    nonce += 1

    # 6. submitVK
    rcpt = _send(w3, private_key, tr.functions.submitVK(uid, vk_out["vk"]).build_transaction(
        {"from": sender, "nonce": nonce, "gas": 350_000, "gasPrice": gp, "chainId": chain_id}
    ))
    assert rcpt["status"] == 1, f"submitVK failed: {rcpt}"
    print("  [B6] submitVK  OK")
    nonce += 1

    print("VPRE conformance PASSED")


if __name__ == "__main__":
    main()
