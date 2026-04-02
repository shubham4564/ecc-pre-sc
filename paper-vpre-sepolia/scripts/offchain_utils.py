import secrets
from math import gcd
from typing import Dict

from web3 import Web3

PRIME_MODULUS = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
GROUP_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
GENERATOR = 5
EXPONENT_MODULUS = PRIME_MODULUS - 1


def mod(a: int, m: int) -> int:
    return a % m


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    return pow(base, exponent, modulus)


def mod_inverse(a: int, m: int) -> int:
    return pow(a, -1, m)


def random_scalar() -> int:
    while True:
        v = secrets.randbits(256)
        if 0 < v < EXPONENT_MODULUS:
            return v


def key_gen() -> Dict[str, int]:
    sk = random_scalar()
    pk = mod_pow(GENERATOR, sk, PRIME_MODULUS)
    return {"sk": sk, "pk": pk}


def hash_to_scalar(values) -> int:
    # We need an invertible scalar for modular division in the finite multiplicative group.
    salt = 0
    while True:
        digest = Web3.solidity_keccak(["uint256"] * (len(values) + 1), [*values, salt])
        scalar = int.from_bytes(digest, "big") % EXPONENT_MODULUS
        if scalar > 1 and gcd(scalar, EXPONENT_MODULUS) == 1:
            return scalar
        salt += 1


def compute_rk(sk_ds: int, pk_db: int, sk_e: int, uid: int) -> Dict[str, int | str]:
    pk_e = mod_pow(GENERATOR, sk_e, PRIME_MODULUS)
    pk_db_pow_sk_e = mod_pow(pk_db, sk_e, PRIME_MODULUS)

    d = hash_to_scalar([uid, pk_e, pk_db, pk_db_pow_sk_e])
    d_inv = mod_inverse(d, EXPONENT_MODULUS)
    rk = mod(sk_ds * d_inv, EXPONENT_MODULUS)

    g_pow_rk = mod_pow(GENERATOR, rk, PRIME_MODULUS)
    cmit = Web3.to_hex(Web3.solidity_keccak(["uint256"], [g_pow_rk]))

    return {"rk": rk, "cmit": cmit, "pk_e": pk_e, "g_pow_rk": g_pow_rk, "d": d}


def compute_vk(pk_ds: int, pk_db: int, sk_db: int, pk_e: int, uid: int) -> Dict[str, int | str]:
    pk_e_pow_sk_db = mod_pow(pk_e, sk_db, PRIME_MODULUS)

    vd = hash_to_scalar([uid, pk_e, pk_db, pk_e_pow_sk_db])
    vd_inv = mod_inverse(vd, EXPONENT_MODULUS)
    vk = mod_pow(pk_ds, vd_inv, PRIME_MODULUS)

    vk_cmit = Web3.to_hex(Web3.solidity_keccak(["uint256"], [vk]))
    return {"vk": vk, "vd": vd, "vk_cmit": vk_cmit}
