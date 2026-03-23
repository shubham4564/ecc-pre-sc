from offchain_utils import key_gen, compute_rk, compute_vk


def main() -> None:
    ds = key_gen()
    db = key_gen()
    sk_e = key_gen()["sk"]

    rk_out = compute_rk(ds["sk"], db["pk"], sk_e)
    vk_out = compute_vk(ds["pk"], db["pk"], db["sk"], rk_out["pk_e"])

    print("=== Off-chain VPRE demo (Python) ===")
    print("DS pk:", ds["pk"])
    print("DB pk:", db["pk"])
    print("PKe:", rk_out["pk_e"])
    print("rk:", rk_out["rk"])
    print("g^rk:", rk_out["g_pow_rk"])
    print("vk:", vk_out["vk"])
    print("cmit from rk:", rk_out["cmit"])
    print("cmit from vk:", vk_out["vk_cmit"])
    print("commitment match:", rk_out["cmit"].lower() == vk_out["vk_cmit"].lower())


if __name__ == "__main__":
    main()
