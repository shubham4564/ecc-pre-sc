from hashlib import sha256

from web3 import Web3


def pseudonym(seed: str) -> bytes:
    return Web3.keccak(text=seed)


def derive_rekey_commitment(owner_private_key: str, data_id: bytes) -> bytes:
    raw = (owner_private_key.lower() + data_id.hex()).encode("utf-8")
    return Web3.keccak(raw)


def derive_transformed_cipher_hash(cipher_hash: bytes, rekey_commitment: bytes, nonce: bytes) -> bytes:
    return Web3.keccak(cipher_hash + rekey_commitment + nonce)


def stable_cipher_hash(payload: bytes) -> bytes:
    return Web3.keccak(sha256(payload).digest())
