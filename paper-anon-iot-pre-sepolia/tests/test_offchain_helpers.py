from pathlib import Path
import sys

from web3 import Web3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from offchain_helpers import derive_rekey_commitment, derive_transformed_cipher_hash, pseudonym  # noqa: E402


def test_pseudonym_deterministic():
    assert pseudonym("owner:x") == pseudonym("owner:x")


def test_rekey_commitment_changes_with_data_id():
    k = "0xabc"
    d1 = Web3.keccak(text="d1")
    d2 = Web3.keccak(text="d2")
    assert derive_rekey_commitment(k, d1) != derive_rekey_commitment(k, d2)


def test_transformed_cipher_hash_bound_to_nonce():
    c = Web3.keccak(text="c")
    rk = Web3.keccak(text="rk")
    n1 = Web3.keccak(text="n1")
    n2 = Web3.keccak(text="n2")
    assert derive_transformed_cipher_hash(c, rk, n1) != derive_transformed_cipher_hash(c, rk, n2)
