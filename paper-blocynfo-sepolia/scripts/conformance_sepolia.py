"""
Sepolia-based conformance smoke-test for BloCyNfo-Share.

Uses the already-deployed contract on Sepolia to verify the core protocol workflow:
  1. storeParams (owner sets system params)
  2. orgRegistration (data-providing org and query org)
  3. approveOrganization (owner approves both)
  4. regPubKey (query org registers its public key)
  5. hashCTI + storeReKey (data org stores re-encryption key)
  6. verify(cti_id, query, c_hash, rk_hash) == True
  7. revokeReKey → verify == False

Exits 0 on success, 1 on any failure.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict

from web3 import Web3

PROJECT = Path(__file__).resolve().parents[1]


def _load_env(path: Path) -> Dict[str, str]:
    env: Dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def _pick_config() -> Dict[str, Any]:
    cfg: Dict[str, str] = {}
    cfg.update(_load_env(PROJECT.parent / ".env"))
    cfg.update(_load_env(PROJECT / ".env"))
    cfg.update({k: v for k, v in os.environ.items()})

    rpc_url = cfg.get("RPC_URL") or cfg.get("ALCHEMY_SEPOLIA_URL")
    api_key = cfg.get("ALCHEMY_API") or cfg.get("ALCHEMY_API_KEY", "")
    if not rpc_url and api_key:
        rpc_url = f"https://eth-sepolia.g.alchemy.com/v2/{api_key}"

    pk = cfg.get("PRIVATE_KEY") or cfg.get("DEPLOYER_PRIVATE_KEY", "")
    if pk and not pk.startswith("0x"):
        pk = "0x" + pk

    return {
        "rpc_url": rpc_url or "",
        "private_key": pk,
        "chain_id": int(cfg.get("CHAIN_ID", "11155111")),
    }


def _find_solc() -> Path:
    candidates = [
        PROJECT / "scripts" / "solc-windows.exe",
        PROJECT.parent / "paper-vpre-sepolia" / "scripts" / "solc-windows.exe",
    ]
    for c in candidates:
        if c.exists():
            return c
    raise RuntimeError("solc-windows.exe not found")


def _compile_abi() -> list:
    solc = _find_solc()
    sources = {}
    for p in (PROJECT / "contracts").glob("*.sol"):
        sources[f"contracts/{p.name}"] = {"content": p.read_text(encoding="utf-8")}
    std_input = {
        "language": "Solidity",
        "sources": sources,
        "settings": {
            "optimizer": {"enabled": True, "runs": 200},
            "outputSelection": {"*": {"*": ["abi"]}},
        },
    }
    proc = subprocess.run([str(solc), "--standard-json"], input=json.dumps(std_input), text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"solc failed: {proc.stderr}")
    out = json.loads(proc.stdout)
    fatal = [e for e in out.get("errors", []) if e.get("severity") == "error"]
    if fatal:
        raise RuntimeError("\n".join(e.get("formattedMessage", str(e)) for e in fatal))
    return out["contracts"]["contracts/BloCyNfoShare.sol"]["BloCyNfoShare"]["abi"]


def _execute(w3: Web3, fn, private_key: str, chain_id: int) -> Dict[str, Any]:
    account = w3.eth.account.from_key(private_key)
    nonce = w3.eth.get_transaction_count(account.address, "pending")
    tx = fn.build_transaction({
        "from": account.address,
        "nonce": nonce,
        "chainId": chain_id,
        "gas": 500_000,
        "gasPrice": w3.eth.gas_price,
    })
    signed = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return dict(w3.eth.wait_for_transaction_receipt(tx_hash))


def main() -> None:
    cfg = _pick_config()
    if not cfg["rpc_url"] or not cfg["private_key"]:
        print("ERROR: Missing RPC_URL or PRIVATE_KEY", file=sys.stderr)
        raise SystemExit(1)

    w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
    if not w3.is_connected():
        print("ERROR: Cannot connect to Sepolia RPC", file=sys.stderr)
        raise SystemExit(1)

    deployment = json.loads((PROJECT / "data" / "deployed.sepolia.json").read_text(encoding="utf-8"))
    c_addr = Web3.to_checksum_address(deployment["bloCyNfoShare"])
    abi = _compile_abi()
    c = w3.eth.contract(address=c_addr, abi=abi)

    account = w3.eth.account.from_key(cfg["private_key"])
    owner = account.address
    chain_id = cfg["chain_id"]

    print(f"BloCyNfo conformance: contract={c_addr}  owner={owner}")

    # 1. storeParams
    params_hash = Web3.keccak(text="conf-params")
    rcpt = _execute(w3, c.functions.storeParams(params_hash, "ipfs://conf/params"), cfg["private_key"], chain_id)
    assert rcpt["status"] == 1, f"storeParams failed: {rcpt}"
    print("  [1] storeParams  OK")

    # 2. orgRegistration for owner as data org and query org (same wallet, different roles)
    org_id = Web3.keccak(text="CONF-ORG")
    query_id = Web3.keccak(text="CONF-QORG")
    rcpt = _execute(w3, c.functions.orgRegistration(org_id, 11, Web3.keccak(text="creds-conf"), Web3.keccak(text="attrs-conf")), cfg["private_key"], chain_id)
    assert rcpt["status"] == 1, f"orgRegistration(org) failed: {rcpt}"
    print("  [2] orgRegistration(org)  OK")

    rcpt = _execute(w3, c.functions.orgRegistration(query_id, 21, Web3.keccak(text="creds-qconf"), Web3.keccak(text="attrs-qconf")), cfg["private_key"], chain_id)
    assert rcpt["status"] == 1, f"orgRegistration(query) failed: {rcpt}"
    print("  [3] orgRegistration(query)  OK")

    # 3. approveOrganization
    rcpt = _execute(w3, c.functions.approveOrganization(owner, True, False), cfg["private_key"], chain_id)
    assert rcpt["status"] == 1, f"approveOrganization(org) failed: {rcpt}"
    print("  [4] approveOrganization(org)  OK")

    rcpt = _execute(w3, c.functions.approveOrganization(owner, True, True), cfg["private_key"], chain_id)
    assert rcpt["status"] == 1, f"approveOrganization(query) failed: {rcpt}"
    print("  [5] approveOrganization(query)  OK")

    # 4. regPubKey
    rcpt = _execute(w3, c.functions.regPubKey(21, Web3.keccak(text="sig-conf-qpk")), cfg["private_key"], chain_id)
    assert rcpt["status"] == 1, f"regPubKey failed: {rcpt}"
    print("  [6] regPubKey  OK")

    # 5. hashCTI + storeReKey  (use timestamp suffix to avoid "cti already exists" on re-runs)
    _ts = str(int(time.time()))
    cti_id = Web3.keccak(text=f"cti-conf-{_ts}")
    c_hash = Web3.keccak(text=f"ciphertext-conf-{_ts}")
    p_hash = Web3.keccak(text=f"policy-conf-{_ts}")
    rk_hash = Web3.keccak(text=f"rk-conf-{_ts}")

    rcpt = _execute(w3, c.functions.hashCTI(cti_id, c_hash, p_hash, "ipfs://cti/conf/1"), cfg["private_key"], chain_id)
    assert rcpt["status"] == 1, f"hashCTI failed: {rcpt}"
    print("  [7] hashCTI  OK")

    rcpt = _execute(w3, c.functions.storeReKey(cti_id, owner, rk_hash, b"rk-conf-bytes"), cfg["private_key"], chain_id)
    assert rcpt["status"] == 1, f"storeReKey failed: {rcpt}"
    print("  [8] storeReKey  OK")

    # 6. verify == True
    result = c.functions.verify(cti_id, owner, c_hash, rk_hash).call()
    assert result is True, f"verify expected True, got {result}"
    print("  [9] verify → True  OK")

    print("BloCyNfo conformance PASSED")


if __name__ == "__main__":
    main()
