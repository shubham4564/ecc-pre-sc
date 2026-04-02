from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from offchain_helpers import derive_rekey_hash  # noqa: E402


def test_rekey_hash_is_bound_to_cti_and_query_org():
    owner_sk = "0xabc123"
    query_pk = 123456789
    policy_hash = "0xdeadbeef"
    cti_a = "0x1111"
    cti_b = "0x2222"
    query_a = "0x00000000000000000000000000000000000000aa"
    query_b = "0x00000000000000000000000000000000000000bb"

    h_a = derive_rekey_hash(owner_sk, query_pk, policy_hash, cti_a, query_a)
    h_b = derive_rekey_hash(owner_sk, query_pk, policy_hash, cti_b, query_a)
    h_c = derive_rekey_hash(owner_sk, query_pk, policy_hash, cti_a, query_b)

    assert h_a != h_b
    assert h_a != h_c
