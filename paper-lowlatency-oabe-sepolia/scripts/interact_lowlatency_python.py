import json
from pathlib import Path

from web3 import Web3

from common import artifact, compile_contracts, execute_fn, load_deployment, pick_config
from offchain_helpers import build_policy_vector, pseudo_mle_encrypt


def main() -> None:
    project_dir = Path(__file__).resolve().parents[1]
    cfg = pick_config(project_dir)

    if not cfg["rpc_url"]:
        raise RuntimeError("Missing RPC_URL or ALCHEMY_SEPOLIA_URL")
    if not cfg["private_key"]:
        raise RuntimeError("Missing PRIVATE_KEY or DEPLOYER_PRIVATE_KEY")

    w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
    if not w3.is_connected():
        raise RuntimeError("RPC connection failed")

    deploy = load_deployment(project_dir)
    compiled = compile_contracts(project_dir)

    acc_art = artifact(compiled, "contracts/ACCSC.sol", "ACCSC")
    ver_art = artifact(compiled, "contracts/VERSC.sol", "VERSC")

    acc = w3.eth.contract(address=deploy["accsc"], abi=acc_art["abi"])
    ver = w3.eth.contract(address=deploy["versc"], abi=ver_art["abi"])

    owner_pk = cfg["private_key"]
    user_pk = cfg["user_private_key"] or cfg["private_key"]
    user = w3.eth.account.from_key(user_pk)

    mtag = Web3.keccak(text="demo-mtag-v1")
    policy = build_policy_vector(cfg["attr_count"], [0, 2, 5])

    message = b"drone:telemetry:frame-001"
    sigma = Web3.keccak(text="sigma-demo")
    phi = bytes.fromhex(deploy["phi"][2:])
    varphi = bytes.fromhex(deploy["varphi"][2:])

    _, _cmle, r_code, h2m, ctag = pseudo_mle_encrypt(message, sigma, phi, varphi)
    h2r = Web3.keccak(r_code)

    tx_map = {}
    rcpt = execute_fn(w3, acc.functions.setTagPolicy(mtag, policy, h2r), owner_pk, cfg["chain_id"])
    tx_map["setTagPolicy"] = rcpt["transactionHash"].hex()

    rcpt = execute_fn(w3, ver.functions.registerCipherMeta(mtag, ctag, h2r), owner_pk, cfg["chain_id"])
    tx_map["registerCipherMeta"] = rcpt["transactionHash"].hex()

    user_attrs_ok = build_policy_vector(cfg["attr_count"], [0, 2, 5, 7])
    rcpt = execute_fn(w3, acc.functions.arrPolicyVerifyCode(mtag, user_attrs_ok, 7, user.address), user_pk, cfg["chain_id"])
    tx_map["arrPolicyVerifyCode"] = rcpt["transactionHash"].hex()

    verify_view = ver.functions.conformVerify(mtag, h2m, h2r).call({"from": user.address})
    rcpt = execute_fn(w3, ver.functions.conformVerifyTx(mtag, h2m, h2r), user_pk, cfg["chain_id"])
    tx_map["conformVerifyTx"] = rcpt["transactionHash"].hex()

    result = {
        "accsc": deploy["accsc"],
        "versc": deploy["versc"],
        "mtag": mtag.hex(),
        "accessExpected": "right",
        "consistencyVerified": bool(verify_view),
        "tx": tx_map,
    }

    out_file = project_dir / "data" / "interaction_result.json"
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    print(f"Saved: {out_file}")


if __name__ == "__main__":
    main()
