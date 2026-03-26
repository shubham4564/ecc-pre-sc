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

    c = out["contracts"]["contracts/SENSHSearchableEncryption.sol"]["SENSHSearchableEncryption"]
    return c["abi"], c["evm"]["bytecode"]["object"]


@pytest.fixture()
def deployed_contract():
    project_dir = Path(__file__).resolve().parents[1]
    abi, bytecode = _compile(project_dir)

    w3 = Web3(EthereumTesterProvider())
    owner = w3.eth.accounts[0]
    user = w3.eth.accounts[1]
    outsider = w3.eth.accounts[2]

    c = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = c.constructor(owner, 4096, 3).transact(_tx_opts(owner))
    rcpt = w3.eth.wait_for_transaction_receipt(tx_hash)
    inst = w3.eth.contract(address=rcpt.contractAddress, abi=abi)
    return w3, inst, owner, user, outsider


def _compute_label(key_material: str, endata: str) -> bytes:
    k1 = Web3.solidity_keccak(["string", "string"], [key_material, "k1"])
    return Web3.solidity_keccak(["bytes32", "string"], [k1, endata])


def test_authorize_and_revoke_flow(deployed_contract):
    w3, c, owner, user, _ = deployed_contract

    assert c.functions.isAuthorized(owner).call() is True
    assert c.functions.isAuthorized(user).call() is False

    c.functions.authorizeUser(user).transact(_tx_opts(owner))
    assert c.functions.isAuthorized(user).call() is True

    c.functions.revokeUser(user).transact(_tx_opts(owner))
    assert c.functions.isAuthorized(user).call() is False


def test_generate_label_token_search(deployed_contract):
    w3, c, owner, user, _ = deployed_contract

    c.functions.authorizeUser(user).transact(_tx_opts(owner))

    key_material = "hospital-key"
    endata = "patient:001:ecg"
    reenc = Web3.keccak(text="renc-001")
    label = _compute_label(key_material, endata)

    c.functions.generateLabel(key_material, endata, reenc).transact(_tx_opts(user))
    c.functions.generateToken(label).transact(_tx_opts(user))

    _, matched = c.functions.search(label).call({"from": user})
    assert matched == reenc

    tx_hash = c.functions.search(label).transact(_tx_opts(user))
    rcpt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert rcpt.status == 1


def test_unauthorized_user_cannot_modify(deployed_contract):
    w3, c, owner, _, outsider = deployed_contract

    tx_hash = c.functions.generateLabel("k", "data", Web3.keccak(text="v")).transact(_tx_opts(outsider))
    rcpt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert rcpt.status == 0


def test_update_label_changes_ciphertext(deployed_contract):
    w3, c, owner, user, _ = deployed_contract

    c.functions.authorizeUser(user).transact(_tx_opts(owner))

    key_material = "hospital-key"
    endata = "patient:002:labs"
    label = _compute_label(key_material, endata)

    v1 = Web3.keccak(text="enc-v1")
    v2 = Web3.keccak(text="enc-v2")

    c.functions.generateLabel(key_material, endata, v1).transact(_tx_opts(user))
    c.functions.updateLabel(label, v2).transact(_tx_opts(user))

    _, matched = c.functions.search(label).call({"from": user})
    assert matched == v2
