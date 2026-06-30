import pytest

from passwolf.model import parse_hash_pair


def test_parse_hash_pair_lm_and_nt():
    lm, nt = parse_hash_pair("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
    assert lm == bytes.fromhex("aad3b435b51404eeaad3b435b51404ee")
    assert nt == bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")


def test_parse_hash_pair_nt_only():
    lm, nt = parse_hash_pair("31d6cfe0d16ae931b73c59d7e0c089c0")
    assert lm is None
    assert nt == bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")


def test_parse_hash_pair_empty():
    assert parse_hash_pair(None) == (None, None)


def test_parse_hash_pair_bad_length():
    with pytest.raises(ValueError):
        parse_hash_pair("deadbeef")
