from hashlib import sha256
from typing import List, Tuple

from web3 import Web3


def h2_bytes(data: bytes) -> bytes:
    return Web3.keccak(data)


def xor32(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def xor_many(values: List[bytes]) -> bytes:
    out = bytes(32)
    for v in values:
        out = xor32(out, v)
    return out


def build_policy_vector(attr_count: int, required_indices: List[int]) -> List[int]:
    out = [0] * attr_count
    for i in required_indices:
        if 0 <= i < attr_count:
            out[i] = 1
    return out


def pseudo_aes_encrypt(message: bytes, k: bytes) -> bytes:
    stream = sha256(k + b"|aes-stream").digest()
    block = (stream * ((len(message) // len(stream)) + 1))[: len(message)]
    return bytes(m ^ b for m, b in zip(message, block))


def pseudo_mle_encrypt(message: bytes, sigma: bytes, phi: bytes, varphi: bytes) -> Tuple[bytes, bytes, bytes, bytes, bytes]:
    r = sha256(message + b"|" + sigma).digest()
    cmle = xor32(sha256(message).digest(), sha256(sigma).digest())
    r_code = sha256(b"R|" + sigma).digest()
    h2m = h2_bytes(message)
    h2r = h2_bytes(r_code)
    ctag = xor_many([phi, varphi, h2m, h2r])
    return r, cmle, r_code, h2m, ctag
