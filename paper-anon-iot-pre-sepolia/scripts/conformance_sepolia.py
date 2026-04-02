"""
Sepolia-based conformance smoke-test for Anonymous IoT PRE.

Uses the already-deployed contract on Sepolia to verify the core protocol workflow:
  1. registerOwner
  2. registerDevice (owner binds device address)
  3. authorizeData (owner authorizes a data item)
  4. submitReKey (owner uploads re-encryption key)
  5. requestReEncryption (device submits request)
  6. approveReEncryption (owner approves)
  7. verifyAccess → True

Exits 0 on success, 1 on any failure.
"""

import json
import sys
from pathlib import Path

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
    contract_address = Web3.to_checksum_address(deployment["iotAnonymousPre"])

    compiled = compile_contracts(PROJECT)
    art = artifact(compiled, "contracts/IoTAnonymousPRE.sol", "IoTAnonymousPRE")
    contract = w3.eth.contract(address=contract_address, abi=art["abi"])

    account = w3.eth.account.from_key(private_key)
    owner = account.address
    chain_id = cfg["chain_id"]

    # For conformance, the same wallet acts as owner and device
    device = owner

    print(f"AnonIoT conformance: contract={contract_address}  owner={owner}")

    # 1. registerOwner — idempotent: reuse existing pseudo if address already bound
    existing_pseudo = contract.functions.ownerPseudoByAddr(owner).call()
    if existing_pseudo != b"\x00" * 32:
        owner_p = existing_pseudo
        print(f"  [1] registerOwner  (already registered, reusing pseudo)  OK")
    else:
        owner_p = Web3.keccak(text="conf-owner-key")
        rcpt = execute_fn(w3, contract.functions.registerOwner(owner_p), private_key, chain_id)
        assert rcpt["status"] == 1, f"registerOwner failed: {rcpt}"
        print("  [1] registerOwner  OK")

    # 2. registerDevice — idempotent: reuse existing device pseudo if already registered
    dev_p = Web3.keccak(text="conf-device-key")
    dev_info = contract.functions.devices(dev_p).call()
    if dev_info[0]:  # exists
        print("  [2] registerDevice  (already registered)  OK")
    else:
        rcpt = execute_fn(w3, contract.functions.registerDevice(owner_p, dev_p, device), private_key, chain_id)
        assert rcpt["status"] == 1, f"registerDevice failed: {rcpt}"
        print("  [2] registerDevice  OK")

    # 3. authorizeData — use timestamp-unique hashes so each run creates a fresh data grant
    import time as _time
    ts = str(int(_time.time()))
    c_hash = Web3.keccak(text=f"conf-cipher-{ts}")
    p_hash = Web3.keccak(text=f"conf-policy-{ts}")
    rcpt = execute_fn(w3, contract.functions.authorizeData(dev_p, c_hash, p_hash), private_key, chain_id)
    assert rcpt["status"] == 1, f"authorizeData failed: {rcpt}"
    print("  [3] authorizeData  OK")

    # 4. submitReKey
    data_id = Web3.solidity_keccak(["bytes32", "bytes32", "bytes32", "bytes32"], [owner_p, dev_p, c_hash, p_hash])
    rekey = Web3.keccak(text=f"conf-rekey-{ts}")
    rcpt = execute_fn(w3, contract.functions.submitReKey(data_id, rekey), private_key, chain_id)
    assert rcpt["status"] == 1, f"submitReKey failed: {rcpt}"
    print("  [4] submitReKey  OK")

    # 5. requestReEncryption — unique nonce per run
    nonce = Web3.keccak(text=f"conf-nonce-{ts}")
    rcpt = execute_fn(w3, contract.functions.requestReEncryption(data_id, nonce), private_key, chain_id)
    assert rcpt["status"] == 1, f"requestReEncryption failed: {rcpt}"
    print("  [5] requestReEncryption  OK")

    # 6. approveReEncryption
    req_id = Web3.solidity_keccak(["bytes32", "address", "bytes32"], [data_id, device, nonce])
    out_h = Web3.keccak(text="conf-output")
    rcpt = execute_fn(w3, contract.functions.approveReEncryption(req_id, out_h), private_key, chain_id)
    assert rcpt["status"] == 1, f"approveReEncryption failed: {rcpt}"
    print("  [6] approveReEncryption  OK")

    # 7. verifyAccess → True
    result = contract.functions.verifyAccess(req_id, out_h).call()
    assert result is True, f"verifyAccess expected True, got {result}"
    print("  [7] verifyAccess → True  OK")

    print("AnonIoT conformance PASSED")


if __name__ == "__main__":
    main()
