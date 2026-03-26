import json
from pathlib import Path

import pytest
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider


def _tx_opts(sender: str) -> dict:
    return {"from": sender, "gas": 8_000_000}


def _find_solc(project_dir: Path) -> Path | None:
    candidates = [
        project_dir / "scripts" / "solc-windows.exe",
        project_dir.parent / "paper-vpre-sepolia" / "scripts" / "solc-windows.exe",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _compile(project_dir: Path):
    import subprocess

    solc = _find_solc(project_dir)
    if not solc:
        pytest.skip("solc-windows.exe missing")

    sources = {}
    for p in (project_dir / "contracts").glob("*.sol"):
        sources[f"contracts/{p.name}"] = {"content": p.read_text(encoding="utf-8")}

    std_input = {
        "language": "Solidity",
        "sources": sources,
        "settings": {
            "optimizer": {"enabled": True, "runs": 200},
            "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object"]}},
        },
    }

    proc = subprocess.run([str(solc), "--standard-json"], input=json.dumps(std_input), text=True, capture_output=True)
    if proc.returncode != 0:
        pytest.fail(proc.stderr)

    out = json.loads(proc.stdout)
    fatal = [e for e in out.get("errors", []) if e.get("severity") == "error"]
    if fatal:
        pytest.fail("\n".join(e.get("formattedMessage", str(e)) for e in fatal))

    c = out["contracts"]["contracts/BloCyNfoShare.sol"]["BloCyNfoShare"]
    return c["abi"], c["evm"]["bytecode"]["object"]


@pytest.fixture()
def deployed_contract():
    project_dir = Path(__file__).resolve().parents[1]
    abi, bytecode = _compile(project_dir)

    w3 = Web3(EthereumTesterProvider())
    owner = w3.eth.accounts[0]
    org = w3.eth.accounts[1]
    query = w3.eth.accounts[2]

    c = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = c.constructor(owner).transact(_tx_opts(owner))
    rcpt = w3.eth.wait_for_transaction_receipt(tx_hash)
    inst = w3.eth.contract(address=rcpt.contractAddress, abi=abi)

    return w3, inst, owner, org, query


def test_happy_path_verify_true(deployed_contract):
    w3, c, owner, org, query = deployed_contract

    c.functions.storeParams(Web3.keccak(text="params"), "ipfs://params").transact(_tx_opts(owner))

    c.functions.orgRegistration(
        Web3.keccak(text="ORG1"),
        11,
        Web3.keccak(text="creds-org"),
        Web3.keccak(text="attrs-org"),
    ).transact(_tx_opts(org))
    c.functions.orgRegistration(
        Web3.keccak(text="ORGQ"),
        21,
        Web3.keccak(text="creds-query"),
        Web3.keccak(text="attrs-query"),
    ).transact(_tx_opts(query))

    c.functions.approveOrganization(org, True, False).transact(_tx_opts(owner))
    c.functions.approveOrganization(query, True, True).transact(_tx_opts(owner))

    c.functions.regPubKey(21, Web3.keccak(text="sig-qpk")).transact(_tx_opts(query))

    cti_id = Web3.keccak(text="cti-1")
    c_hash = Web3.keccak(text="ciphertext")
    p_hash = Web3.keccak(text="policy")
    rk_hash = Web3.keccak(text="rk-hash")

    c.functions.hashCTI(cti_id, c_hash, p_hash, "ipfs://cti/1").transact(_tx_opts(org))
    c.functions.storeReKey(cti_id, query, rk_hash, b"rk-bytes").transact(_tx_opts(org))

    assert c.functions.verify(cti_id, query, c_hash, rk_hash).call() is True


def test_verify_false_after_revoke(deployed_contract):
    w3, c, owner, org, query = deployed_contract

    c.functions.orgRegistration(Web3.keccak(text="ORG1"), 11, Web3.keccak(text="c1"), Web3.keccak(text="a1")).transact(_tx_opts(org))
    c.functions.orgRegistration(Web3.keccak(text="ORGQ"), 21, Web3.keccak(text="c2"), Web3.keccak(text="a2")).transact(_tx_opts(query))

    c.functions.approveOrganization(org, True, False).transact(_tx_opts(owner))
    c.functions.approveOrganization(query, True, True).transact(_tx_opts(owner))
    c.functions.regPubKey(21, Web3.keccak(text="sig-qpk")).transact(_tx_opts(query))

    cti_id = Web3.keccak(text="cti-2")
    c_hash = Web3.keccak(text="ciphertext2")
    p_hash = Web3.keccak(text="policy2")
    rk_hash = Web3.keccak(text="rk-hash2")

    c.functions.hashCTI(cti_id, c_hash, p_hash, "ipfs://cti/2").transact(_tx_opts(org))
    c.functions.storeReKey(cti_id, query, rk_hash, b"rk2").transact(_tx_opts(org))
    c.functions.revokeReKey(cti_id, query).transact(_tx_opts(org))

    assert c.functions.verify(cti_id, query, c_hash, rk_hash).call() is False


def test_only_cti_owner_can_store_rekey(deployed_contract):
    w3, c, owner, org, query = deployed_contract
    outsider = w3.eth.accounts[3]

    c.functions.orgRegistration(Web3.keccak(text="ORG1"), 11, Web3.keccak(text="c1"), Web3.keccak(text="a1")).transact(_tx_opts(org))
    c.functions.orgRegistration(Web3.keccak(text="ORGQ"), 21, Web3.keccak(text="c2"), Web3.keccak(text="a2")).transact(_tx_opts(query))
    c.functions.orgRegistration(Web3.keccak(text="ORGO"), 31, Web3.keccak(text="c3"), Web3.keccak(text="a3")).transact(_tx_opts(outsider))

    c.functions.approveOrganization(org, True, False).transact(_tx_opts(owner))
    c.functions.approveOrganization(query, True, True).transact(_tx_opts(owner))
    c.functions.approveOrganization(outsider, True, False).transact(_tx_opts(owner))

    cti_id = Web3.keccak(text="cti-3")
    c.functions.hashCTI(cti_id, Web3.keccak(text="cti3"), Web3.keccak(text="policy3"), "ipfs://cti/3").transact(_tx_opts(org))

    tx_hash = c.functions.storeReKey(cti_id, query, Web3.keccak(text="rk"), b"rk").transact(_tx_opts(outsider))
    rcpt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert rcpt.status == 0
