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

    acc = out["contracts"]["contracts/ACCSC.sol"]["ACCSC"]
    ver = out["contracts"]["contracts/VERSC.sol"]["VERSC"]
    return {
        "acc": (acc["abi"], acc["evm"]["bytecode"]["object"]),
        "ver": (ver["abi"], ver["evm"]["bytecode"]["object"]),
    }


@pytest.fixture()
def deployed_contracts():
    project_dir = Path(__file__).resolve().parents[1]
    comp = _compile(project_dir)

    w3 = Web3(EthereumTesterProvider())
    owner = w3.eth.accounts[0]
    user = w3.eth.accounts[1]

    acc_abi, acc_bytecode = comp["acc"]
    ver_abi, ver_bytecode = comp["ver"]

    acc = w3.eth.contract(abi=acc_abi, bytecode=acc_bytecode)
    tx_hash = acc.constructor(owner, 100, 8).transact(_tx_opts(owner))
    acc_addr = w3.eth.wait_for_transaction_receipt(tx_hash).contractAddress
    acc_inst = w3.eth.contract(address=acc_addr, abi=acc_abi)

    phi = Web3.keccak(text="phi")
    varphi = Web3.keccak(text="varphi")

    ver = w3.eth.contract(abi=ver_abi, bytecode=ver_bytecode)
    tx_hash = ver.constructor(owner, phi, varphi).transact(_tx_opts(owner))
    ver_addr = w3.eth.wait_for_transaction_receipt(tx_hash).contractAddress
    ver_inst = w3.eth.contract(address=ver_addr, abi=ver_abi)

    return w3, acc_inst, ver_inst, owner, user, phi, varphi


def test_access_policy_right_path(deployed_contracts):
    w3, acc, _, owner, user, _, _ = deployed_contracts
    mtag = Web3.keccak(text="tag-1")
    policy = [1, 0, 1, 0, 0, 1, 0, 0]

    acc.functions.setTagPolicy(mtag, policy, Web3.keccak(text="h2r")).transact(_tx_opts(owner))

    user_attrs_ok = [1, 0, 1, 0, 0, 1, 0, 1]
    code = acc.functions.arrPolicyVerifyCode(mtag, user_attrs_ok, 1, user).call({"from": user})
    assert code == 1


def test_access_policy_punishment_flow(deployed_contracts):
    w3, acc, _, owner, user, _, _ = deployed_contracts
    mtag = Web3.keccak(text="tag-2")
    policy = [1, 1, 1, 0, 0, 0, 0, 0]
    acc.functions.setTagPolicy(mtag, policy, Web3.keccak(text="h2r")).transact(_tx_opts(owner))

    bad_user_attrs = [1, 0, 0, 0, 0, 0, 0, 0]

    for _ in range(5):
        acc.functions.arrPolicyVerifyCode(mtag, bad_user_attrs, 9, user).transact(_tx_opts(user))

    # Fifth call enters punished branch.
    code = acc.functions.arrPolicyVerifyCode(mtag, bad_user_attrs, 9, user).call({"from": user})
    assert code == 2


def test_consistency_verify_success(deployed_contracts):
    w3, _, ver, owner, user, phi, varphi = deployed_contracts

    mtag = Web3.keccak(text="tag-3")
    h2m = Web3.keccak(text="h2m")
    h2r = Web3.keccak(text="h2r")
    ctag = bytes(x ^ y ^ z ^ t for x, y, z, t in zip(phi, varphi, h2m, h2r))

    ver.functions.registerCipherMeta(mtag, ctag, h2r).transact(_tx_opts(owner))
    assert ver.functions.conformVerify(mtag, h2m, h2r).call({"from": user}) is True


def test_consistency_verify_failure_invalid_input(deployed_contracts):
    w3, _, ver, owner, user, phi, varphi = deployed_contracts

    mtag = Web3.keccak(text="tag-4")
    h2m = Web3.keccak(text="h2m")
    h2r = Web3.keccak(text="h2r")
    ctag = bytes(x ^ y ^ z ^ t for x, y, z, t in zip(phi, varphi, h2m, h2r))

    ver.functions.registerCipherMeta(mtag, ctag, h2r).transact(_tx_opts(owner))
    wrong_h2m = Web3.keccak(text="h2m-wrong")
    assert ver.functions.conformVerify(mtag, wrong_h2m, h2r).call({"from": user}) is False
