import json
from hashlib import sha256
from typing import Iterable

from web3 import Web3


def canonical_attr_hash(attributes: Iterable[str]) -> str:
    attrs = sorted(a.strip().lower() for a in attributes if a.strip())
    digest = Web3.keccak(text="|".join(attrs))
    return Web3.to_hex(digest)


def policy_hash(policy_tree: dict) -> str:
    canonical = json.dumps(policy_tree, sort_keys=True, separators=(",", ":"))
    return Web3.to_hex(Web3.keccak(text=canonical))


def cti_hash(ciphertext: bytes) -> str:
    return Web3.to_hex(Web3.keccak(ciphertext))


def derive_rekey_hash(owner_sk_hex: str, query_pk_int: int, policy_hash_hex: str) -> str:
    material = f"{owner_sk_hex.lower()}|{query_pk_int}|{policy_hash_hex.lower()}".encode("utf-8")
    return "0x" + sha256(material).hexdigest()


def derive_rekey_blob(owner_sk_hex: str, query_pk_int: int, policy_hash_hex: str) -> bytes:
    # Placeholder blob for benchmark-friendly prototype; actual CP-ABPRE payload remains off-chain.
    return f"rk:{derive_rekey_hash(owner_sk_hex, query_pk_int, policy_hash_hex)}".encode("utf-8")
