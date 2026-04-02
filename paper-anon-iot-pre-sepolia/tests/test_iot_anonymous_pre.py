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

    c = out["contracts"]["contracts/IoTAnonymousPRE.sol"]["IoTAnonymousPRE"]
    return c["abi"], c["evm"]["bytecode"]["object"]


@pytest.fixture()
def deployed_contract():
    project_dir = Path(__file__).resolve().parents[1]
    abi, bytecode = _compile(project_dir)

    w3 = Web3(EthereumTesterProvider())
    backend_name = type(w3.provider.ethereum_tester.backend).__name__.lower()
    if "mock" in backend_name:
        pytest.skip("eth-tester MockBackend active; install py-evm for contract execution tests")

    owner = w3.eth.accounts[0]
    device = w3.eth.accounts[1]
    outsider = w3.eth.accounts[2]

    c = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = c.constructor().transact(_tx_opts(owner))
    rcpt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if not rcpt.contractAddress:
        pytest.skip("contract deployment unsupported in current eth-tester backend")

    inst = w3.eth.contract(address=rcpt.contractAddress, abi=abi)
    return w3, inst, owner, device, outsider


def test_happy_path(deployed_contract):
    w3, c, owner, device, _ = deployed_contract

    owner_p = Web3.keccak(text="owner")
    dev_p = Web3.keccak(text="device")
    c_hash = Web3.keccak(text="cipher")
    p_hash = Web3.keccak(text="policy")

    c.functions.registerOwner(owner_p).transact(_tx_opts(owner))
    c.functions.registerDevice(owner_p, dev_p, device).transact(_tx_opts(owner))
    c.functions.authorizeData(dev_p, c_hash, p_hash).transact(_tx_opts(owner))

    data_id = Web3.solidity_keccak(["bytes32", "bytes32", "bytes32", "bytes32"], [owner_p, dev_p, c_hash, p_hash])
    rekey = Web3.keccak(text="rk")
    c.functions.submitReKey(data_id, rekey).transact(_tx_opts(owner))

    nonce = Web3.keccak(text="n1")
    c.functions.requestReEncryption(data_id, nonce).transact(_tx_opts(device))

    req_id = Web3.solidity_keccak(["bytes32", "address", "bytes32"], [data_id, device, nonce])
    out_h = Web3.keccak(text="out")
    c.functions.approveReEncryption(req_id, out_h).transact(_tx_opts(owner))

    assert c.functions.verifyAccess(req_id, out_h).call() is True


def test_only_bound_device_can_request(deployed_contract):
    w3, c, owner, device, outsider = deployed_contract

    owner_p = Web3.keccak(text="owner2")
    dev_p = Web3.keccak(text="device2")
    c_hash = Web3.keccak(text="cipher2")
    p_hash = Web3.keccak(text="policy2")

    c.functions.registerOwner(owner_p).transact(_tx_opts(owner))
    c.functions.registerDevice(owner_p, dev_p, device).transact(_tx_opts(owner))
    c.functions.authorizeData(dev_p, c_hash, p_hash).transact(_tx_opts(owner))

    data_id = Web3.solidity_keccak(["bytes32", "bytes32", "bytes32", "bytes32"], [owner_p, dev_p, c_hash, p_hash])
    c.functions.submitReKey(data_id, Web3.keccak(text="rk2")).transact(_tx_opts(owner))

    tx = c.functions.requestReEncryption(data_id, Web3.keccak(text="bad")).transact(_tx_opts(outsider))
    rcpt = w3.eth.wait_for_transaction_receipt(tx)
    assert rcpt.status == 0
