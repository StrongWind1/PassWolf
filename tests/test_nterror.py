# SPDX-License-Identifier: Apache-2.0
from passwolf import nterror


def test_is_success():
    assert nterror.is_success(0x00000000)
    assert not nterror.is_success(0xC000006A)


def test_name_known():
    assert nterror.name(0xC000006A) == "STATUS_WRONG_PASSWORD"
    assert nterror.name(0xC000006C) == "STATUS_PASSWORD_RESTRICTION"


def test_name_unmapped_is_hex():
    assert nterror.name(0xDEADBEEF) == "0xDEADBEEF"


def test_describe_includes_code_and_text():
    described = nterror.describe(0xC0000022)
    assert "STATUS_ACCESS_DENIED" in described
    assert "0xC0000022" in described


def test_describe_unmapped():
    assert "unmapped" in nterror.describe(0x12345678)
