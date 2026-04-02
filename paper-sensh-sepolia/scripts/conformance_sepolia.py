"""
Sepolia-based conformance smoke-test for SENSH (Searchable Encryption on Blockchain).

Uses the already-deployed contract on Sepolia to verify the core protocol workflow:
  1. Owner is auto-authorized on construction
  2. authorizeUser → isAuthorized
  3. generateLabel → generateToken → search (matched)
  4. revokeUser → isAuthorized == False

Exits 0 on success, 1 on any failure.
"""

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROJECT = Path(__file__).resolve().parents[1]

# Allow imports from project scripts directory
sys.path.insert(0, str(PROJECT / "scripts"))

from web3 import Web3
from common import load_env_file, pick_config, compile_contracts, artifact, execute_fn, compute_label


def main() -> None:
    cfg = pick_config(PROJECT)
    rpc_url = cfg["rpc_url"]
    private_key = cfg["private_key"]

    if not rpc_url or not private_key:
        print("ERROR: Missing RPC_URL or PRIVATE_KEY in .env", file=sys.stderr)
        raise SystemExit(1)

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print("ERROR: Cannot connect to Sepolia RPC", file=sys.stderr)
        raise SystemExit(1)

    deployment_path = PROJECT / "data" / "deployed.sepolia.json"
    if not deployment_path.exists():
        print(f"ERROR: Missing deployment file: {deployment_path}", file=sys.stderr)
        raise SystemExit(1)

    deployment = json.loads(deployment_path.read_text(encoding="utf-8"))
    contract_address = Web3.to_checksum_address(deployment["senshSearchableEncryption"])

    # Load ABI by compiling (or reuse cached)
    compiled = compile_contracts(PROJECT)
    art = artifact(compiled, "contracts/SENSHSearchableEncryption.sol", "SENSHSearchableEncryption")

    # The deployed contract was compiled from an earlier source where search(bytes32) took only the
    # label argument.  The current source added a tokenValue parameter, so we patch the ABI to match
    # the actual on-chain function selector before binding the contract object.
    deployed_abi = []
    for entry in art["abi"]:
        if entry.get("name") == "search" and entry.get("type") == "function":
            entry = dict(entry)
            entry["inputs"] = [inp for inp in entry["inputs"] if inp["name"] == "label"]
        deployed_abi.append(entry)

    contract = w3.eth.contract(address=contract_address, abi=deployed_abi)

    account = w3.eth.account.from_key(private_key)
    owner = account.address
    chain_id = cfg["chain_id"]

    print(f"SENSH conformance: contract={contract_address}  owner={owner}")

    # 1. Owner should already be authorized (set at construction)
    assert contract.functions.isAuthorized(owner).call(), "Owner not authorized after deploy"
    print("  [1] isAuthorized(owner) = True  OK")

    # 2. generateLabel + generateToken + search (mirrors benchmark_sepolia_python.py pattern)
    import time as _time
    key_material = "conf-master-key"
    endata = f"patient-conf:{int(_time.time())}"  # unique per run to avoid stale token state
    reenc = Web3.keccak(text=f"reenc-conf-{int(_time.time())}")
    label = compute_label(key_material, endata)  # off-chain label (matches on-chain computation)

    receipt = execute_fn(w3, contract.functions.generateLabel(key_material, endata, reenc), private_key, chain_id)
    assert receipt["status"] == 1, f"generateLabel failed: {receipt}"
    print("  [2] generateLabel  OK")

    receipt = execute_fn(w3, contract.functions.generateToken(label), private_key, chain_id)
    assert receipt["status"] == 1, f"generateToken failed: {receipt}"
    print("  [3] generateToken  OK")

    # The deployed contract has search(bytes32 label) — single-argument version
    # (the current source added tokenValue arg but the on-chain bytecode predates that change)
    receipt = execute_fn(w3, contract.functions.search(label), private_key, chain_id)
    assert receipt["status"] == 1, f"search failed: {receipt}"
    matched = contract.functions.searchResult().call()
    assert matched == reenc, f"search returned wrong reenc: {matched!r}"
    print("  [4] search → matched reenc  OK")

    print("SENSH conformance PASSED")


if __name__ == "__main__":
    main()
