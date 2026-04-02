"""
Sepolia-based conformance smoke-test for Low-Latency OABE.

Uses already-deployed ACCSC and VERSC contracts on Sepolia to verify core protocol:
  1. ACCSC: setTagPolicy → arrPolicyVerifyCode returns 1 (authorized)
  2. VERSC: registerCipherMeta → conformVerify returns True (consistent)

Exits 0 on success, 1 on any failure.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

from web3 import Web3

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "scripts"))

from common import pick_config, compile_contracts, artifact, execute_fn


def main() -> None:
    cfg = pick_config(PROJECT)
    rpc_url = cfg["rpc_url"]
    private_key = cfg["private_key"]

    if not rpc_url or not private_key:
        print("ERROR: Missing RPC_URL or PRIVATE_KEY", file=sys.stderr)
        raise SystemExit(1)

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print("ERROR: Cannot connect to Sepolia RPC", file=sys.stderr)
        raise SystemExit(1)

    deployment = json.loads((PROJECT / "data" / "deployed.sepolia.json").read_text(encoding="utf-8"))
    acc_addr = Web3.to_checksum_address(deployment["accsc"])
    ver_addr = Web3.to_checksum_address(deployment["versc"])
    phi = bytes.fromhex(deployment["phi"].lstrip("0x"))
    varphi = bytes.fromhex(deployment["varphi"].lstrip("0x"))

    compiled = compile_contracts(PROJECT)
    acc_abi = artifact(compiled, "contracts/ACCSC.sol", "ACCSC")["abi"]
    ver_abi = artifact(compiled, "contracts/VERSC.sol", "VERSC")["abi"]

    acc = w3.eth.contract(address=acc_addr, abi=acc_abi)
    ver = w3.eth.contract(address=ver_addr, abi=ver_abi)

    account = w3.eth.account.from_key(private_key)
    owner = account.address
    chain_id = cfg["chain_id"]

    print(f"LowLatency conformance: ACCSC={acc_addr}  VERSC={ver_addr}  owner={owner}")

    # 1. ACCSC: setTagPolicy
    mtag = Web3.keccak(text="conf-tag-acc-1")
    policy = [1, 0, 1, 0, 0, 1, 0, 0]
    rcpt = execute_fn(w3, acc.functions.setTagPolicy(mtag, policy, Web3.keccak(text="conf-h2r")), private_key, chain_id)
    assert rcpt["status"] == 1, f"setTagPolicy failed: {rcpt}"
    print("  [1] setTagPolicy  OK")

    # 2. ACCSC: arrPolicyVerifyCode → expect 1 (authorized)
    user_attrs_ok = [1, 0, 1, 0, 0, 1, 0, 1]
    code = acc.functions.arrPolicyVerifyCode(mtag, user_attrs_ok, 1, owner).call({"from": owner})
    assert code == 1, f"arrPolicyVerifyCode expected 1, got {code}"
    print("  [2] arrPolicyVerifyCode → 1 (authorized)  OK")

    # 3. VERSC: registerCipherMeta
    mtag_ver = Web3.keccak(text="conf-tag-ver-1")
    h2m = Web3.keccak(text="conf-h2m")
    h2r = Web3.keccak(text="conf-h2r-ver")
    ctag = bytes(x ^ y ^ z ^ t for x, y, z, t in zip(phi, varphi, h2m, h2r))

    rcpt = execute_fn(w3, ver.functions.registerCipherMeta(mtag_ver, ctag, h2r), private_key, chain_id)
    assert rcpt["status"] == 1, f"registerCipherMeta failed: {rcpt}"
    print("  [3] registerCipherMeta  OK")

    # 4. VERSC: conformVerify → True
    result = ver.functions.conformVerify(mtag_ver, h2m, h2r).call({"from": owner})
    assert result is True, f"conformVerify expected True, got {result}"
    print("  [4] conformVerify → True  OK")

    print("LowLatency conformance PASSED")


if __name__ == "__main__":
    main()
