from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from offchain_helpers import pseudo_aes_encrypt, pseudo_aes_decrypt, pseudo_mle_encrypt  # noqa: E402


def test_aes_gcm_roundtrip():
    msg = b"drone-telemetry-payload"
    key_seed = b"sigma-for-aes"

    blob = pseudo_aes_encrypt(msg, key_seed)
    dec = pseudo_aes_decrypt(blob, key_seed)

    assert dec == msg
    assert blob != msg


def test_mle_tag_changes_with_context():
    msg = b"same-message"
    sigma_1 = b"sigma-1"
    sigma_2 = b"sigma-2"
    phi = bytes([1] * 32)
    varphi = bytes([2] * 32)

    _, _, _, _, ctag_1 = pseudo_mle_encrypt(msg, sigma_1, phi, varphi)
    _, _, _, _, ctag_2 = pseudo_mle_encrypt(msg, sigma_2, phi, varphi)

    assert ctag_1 != ctag_2
