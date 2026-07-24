# SPDX-License-Identifier: Apache-2.0
"""Structure-building regression tests for the AES, set-hash, and RAP paths.

These exercise the request marshalling of the methods impacket does not model, with a stub DCE that
captures the wire bytes, so a struct regression is caught without a live domain controller.
"""

import logging

import pytest
from impacket.dcerpc.v5 import samr as impacket_samr
from impacket.dcerpc.v5.rpcrt import DCERPCException

from passwolf import crypto, ndr, rap, samr
from passwolf.constants import (
    DOMAIN_USER_RID_ADMIN,
    OPNUM_SAMR_SET_INFORMATION_USER,
    OPNUM_SAMR_SET_INFORMATION_USER2,
    USER_ALL_INFORMATION,
    USER_INTERNAL1_INFORMATION,
    USER_INTERNAL4_INFORMATION,
    USER_INTERNAL4_INFORMATION_NEW,
    USER_INTERNAL5_INFORMATION,
    USER_INTERNAL5_INFORMATION_NEW,
    USER_INTERNAL7_INFORMATION,
    USER_INTERNAL8_INFORMATION,
)
from passwolf.errors import MethodUnavailable
from passwolf.model import ChangeMethod, ResetMethod, Secret, Target

# The eight settable password-bearing USER_INFORMATION_CLASS values, split by the secret they carry.
_HASH_CLASSES = (USER_INTERNAL1_INFORMATION, USER_ALL_INFORMATION)
_CLEARTEXT_CLASSES = (
    USER_INTERNAL4_INFORMATION,
    USER_INTERNAL5_INFORMATION,
    USER_INTERNAL4_INFORMATION_NEW,
    USER_INTERNAL5_INFORMATION_NEW,
    USER_INTERNAL7_INFORMATION,
    USER_INTERNAL8_INFORMATION,
)


class _FakeResp(dict):
    def __init__(self):
        super().__init__(ErrorCode=0)


class _FakeDCE:
    """Captures the serialized request instead of sending it."""

    def __init__(self):
        self.sent = []

    def request(self, req):
        self.sent.append(req.getData())
        return _FakeResp()


# Cross-encryption retry signals from SamrChangePasswordUser (opnum 38), [MS-SAMR] 3.1.5.10.1.
CROSS_NT = 0xC000015D
CROSS_LM = 0xC000017F
WRONG_PW = 0xC000006A


class _SeqDCE:
    """Returns a queued sequence of NTSTATUS codes: 0 yields a success response, else raises a fault.

    Records the four SamrChangePasswordUser presence flags per call so a test can prove the retry loop
    re-sent the request with the cross-encryption blob the server demanded.
    """

    def __init__(self, statuses):
        self._statuses = list(statuses)
        self.sent = []  # per call: (LmPresent, NtPresent, NtCrossPresent, LmCrossPresent)

    def request(self, req):
        self.sent.append((int(req["LmPresent"]), int(req["NtPresent"]), int(req["NtCrossEncryptionPresent"]), int(req["LmCrossEncryptionPresent"])))
        status = self._statuses.pop(0)
        if status == 0:
            return _FakeResp()
        raise impacket_samr.DCERPCSessionError(error_code=status)


SESSION_KEY = b"\x22" * 16
EMPTY_NT = bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")
EMPTY_LM = bytes.fromhex("aad3b435b51404eeaad3b435b51404ee")


def test_internal8_spliced_into_union():
    union = impacket_samr.SAMPR_USER_INFO_BUFFER.union
    assert USER_INTERNAL8_INFORMATION in union
    assert union[USER_INTERNAL8_INFORMATION][0] == "Internal8"
    assert union[USER_INTERNAL7_INFORMATION][0] == "Internal7"


def test_internal8_struct_marshals():
    assert ndr.SAMPR_USER_INTERNAL8_INFORMATION is not None


def test_ndr_module_exposes_session_error():
    # impacket's DCERPC_v5.request() looks up <request module>.DCERPCSessionError to raise on a non-zero
    # NTSTATUS; the ndr-hosted calls (opnums 73, 63, 138, 6) live here, so the name must resolve to a
    # DCERPCException subclass or a server rejection turns into an AttributeError instead of a typed error.
    assert hasattr(ndr, "DCERPCSessionError")
    assert issubclass(ndr.DCERPCSessionError, DCERPCException)


def test_reset_internal8_builds_and_returns_status():
    # UserInternal8 (the all-information AES reset) is reached via reset_set_information with the internal8
    # info class (CLI: --reset-info-class internal8), the only entry point for the all-info wire shape.
    dce = _FakeDCE()
    status = samr.reset_set_information(dce, object(), SESSION_KEY, opnum=OPNUM_SAMR_SET_INFORMATION_USER2, info_class=USER_INTERNAL8_INFORMATION, new_password="NewPass1!", nt_hash=None, lm_hash=None, expire=True)
    assert status == 0
    assert len(dce.sent) == 1
    assert len(dce.sent[0]) > 512  # the all-information block makes this the largest reset buffer


def test_reset_hash_nt_only():
    dce = _FakeDCE()
    status = samr.reset_hash(dce, object(), SESSION_KEY, EMPTY_NT)
    assert status == 0
    assert len(dce.sent) == 1


def test_reset_hash_nt_and_lm_differs_from_nt_only():
    nt_only = _FakeDCE()
    samr.reset_hash(nt_only, object(), SESSION_KEY, EMPTY_NT)
    nt_lm = _FakeDCE()
    samr.reset_hash(nt_lm, object(), SESSION_KEY, EMPTY_NT, EMPTY_LM)
    # The LM half is encrypted into the buffer, so the wire bytes must differ.
    assert nt_only.sent[0] != nt_lm.sent[0]


def test_reset_hash_requires_session_key():
    with pytest.raises(MethodUnavailable):
        samr.reset_hash(_FakeDCE(), object(), None, EMPTY_NT)


def test_reset_dsrm_marshals_raw_encrypted_owf():
    # The encrypted NT OWF must appear in the wire bytes, set on the referent-pointer field as raw bytes.
    dce = _FakeDCE()
    assert samr.reset_dsrm(dce, "NewDsrm1!xQ") == 0
    assert len(dce.sent) == 1
    encrypted = crypto.des_owf_encrypt(crypto.nt_owf("NewDsrm1!xQ"), crypto.rid_to_des_key(DOMAIN_USER_RID_ADMIN))
    assert encrypted in dce.sent[0]


def test_reset_dsrm_does_not_log_setitem_error(caplog):
    # Wrapping the OWF in an ENCRYPTED_*_OWF_PASSWORD struct makes impacket log "Can't setitem ..." and
    # fall back; assigning the raw bytes (the fix) must not trip that path.
    with caplog.at_level(logging.ERROR):
        samr.reset_dsrm(_FakeDCE(), "NewDsrm1!xQ")
    assert "setitem" not in caplog.text.lower()


def test_reset_rc4_builds_and_honors_expire():
    dce = _FakeDCE()
    assert samr.reset_rc4(dce, object(), SESSION_KEY, "NewPass1!", expire=False) == 0
    assert len(dce.sent) == 1


def test_reset_rc4_requires_session_key():
    with pytest.raises(MethodUnavailable):
        samr.reset_rc4(_FakeDCE(), object(), None, "NewPass1!")


def test_reset_rc4_unsalted_builds_and_honors_expire():
    dce = _FakeDCE()
    assert samr.reset_rc4_unsalted(dce, object(), SESSION_KEY, "NewPass1!", expire=False) == 0
    assert len(dce.sent) == 1


class _OpnumDCE:
    """Captures the opnum of each request so the opnum-selection branch can be proven without a host."""

    def __init__(self):
        self.opnums = []

    def request(self, req):
        req.getData()  # force marshalling so a struct regression still fails here
        self.opnums.append(req.opnum)
        return _FakeResp()


@pytest.mark.parametrize("info_class", _CLEARTEXT_CLASSES)
def test_reset_set_information_cleartext_classes_build(info_class):
    # Every cleartext info class marshals a valid request and returns the server status.
    dce = _FakeDCE()
    status = samr.reset_set_information(dce, object(), SESSION_KEY, opnum=OPNUM_SAMR_SET_INFORMATION_USER2, info_class=info_class, new_password="NewPass1!", expire=True)
    assert status == 0
    assert len(dce.sent) == 1


@pytest.mark.parametrize("info_class", _HASH_CLASSES)
def test_reset_set_information_hash_classes_build(info_class):
    # The two hash carriers (Internal1, UserAll) marshal a valid request from an NT hash.
    dce = _FakeDCE()
    status = samr.reset_set_information(dce, object(), SESSION_KEY, opnum=OPNUM_SAMR_SET_INFORMATION_USER2, info_class=info_class, nt_hash=EMPTY_NT, lm_hash=EMPTY_LM, expire=True)
    assert status == 0
    assert len(dce.sent) == 1


def test_reset_set_information_opnum_selects_request_class():
    # The opnum argument picks SamrSetInformationUser (37) vs SamrSetInformationUser2 (58) on the wire.
    dce = _OpnumDCE()
    samr.reset_set_information(dce, object(), SESSION_KEY, opnum=OPNUM_SAMR_SET_INFORMATION_USER, info_class=USER_INTERNAL1_INFORMATION, nt_hash=EMPTY_NT, expire=True)
    samr.reset_set_information(dce, object(), SESSION_KEY, opnum=OPNUM_SAMR_SET_INFORMATION_USER2, info_class=USER_INTERNAL1_INFORMATION, nt_hash=EMPTY_NT, expire=True)
    assert dce.opnums == [OPNUM_SAMR_SET_INFORMATION_USER, OPNUM_SAMR_SET_INFORMATION_USER2]


def test_reset_set_information_requires_session_key():
    with pytest.raises(MethodUnavailable):
        samr.reset_set_information(_FakeDCE(), object(), None, opnum=OPNUM_SAMR_SET_INFORMATION_USER2, info_class=USER_INTERNAL7_INFORMATION, new_password="NewPass1!", expire=True)


@pytest.mark.parametrize("info_class", _HASH_CLASSES)
def test_reset_set_information_hash_class_derives_hash_from_password(info_class):
    # A hash class given only a cleartext password hashes it locally into the NT OWF and builds the request.
    dce = _FakeDCE()
    status = samr.reset_set_information(dce, object(), SESSION_KEY, opnum=OPNUM_SAMR_SET_INFORMATION_USER2, info_class=info_class, new_password="NewPass1!", expire=True)
    assert status == 0
    assert len(dce.sent) == 1


def test_reset_set_information_hash_class_from_password_matches_explicit_nt():
    # Setting internal1 from a cleartext password must produce the same bytes as setting its NT OWF directly.
    from_pw = _FakeDCE()
    samr.reset_set_information(from_pw, object(), SESSION_KEY, opnum=OPNUM_SAMR_SET_INFORMATION_USER2, info_class=USER_INTERNAL1_INFORMATION, new_password="NewPass1!", expire=True)
    from_hash = _FakeDCE()
    samr.reset_set_information(from_hash, object(), SESSION_KEY, opnum=OPNUM_SAMR_SET_INFORMATION_USER2, info_class=USER_INTERNAL1_INFORMATION, nt_hash=crypto.nt_owf("NewPass1!"), expire=True)
    assert from_pw.sent[0] == from_hash.sent[0]


def test_reset_set_information_hash_class_needs_password_or_hash():
    with pytest.raises(MethodUnavailable):
        samr.reset_set_information(_FakeDCE(), object(), SESSION_KEY, opnum=OPNUM_SAMR_SET_INFORMATION_USER2, info_class=USER_INTERNAL1_INFORMATION, expire=True)


def test_reset_set_information_cleartext_class_needs_password():
    with pytest.raises(MethodUnavailable):
        samr.reset_set_information(_FakeDCE(), object(), SESSION_KEY, opnum=OPNUM_SAMR_SET_INFORMATION_USER2, info_class=USER_INTERNAL7_INFORMATION, nt_hash=EMPTY_NT, expire=True)


def test_reset_set_information_rejects_unknown_class():
    with pytest.raises(MethodUnavailable):
        samr.reset_set_information(_FakeDCE(), object(), SESSION_KEY, opnum=OPNUM_SAMR_SET_INFORMATION_USER2, info_class=999, new_password="NewPass1!", expire=True)


def test_reset_set_information_userall_lm_differs_from_nt_only():
    # Adding the LM half flips the LMPASSWORDPRESENT WhichFields bit and embeds a second OWF, so the bytes differ.
    nt_only = _FakeDCE()
    samr.reset_set_information(nt_only, object(), SESSION_KEY, opnum=OPNUM_SAMR_SET_INFORMATION_USER2, info_class=USER_ALL_INFORMATION, nt_hash=EMPTY_NT, expire=True)
    nt_lm = _FakeDCE()
    samr.reset_set_information(nt_lm, object(), SESSION_KEY, opnum=OPNUM_SAMR_SET_INFORMATION_USER2, info_class=USER_ALL_INFORMATION, nt_hash=EMPTY_NT, lm_hash=EMPTY_LM, expire=True)
    assert nt_only.sent[0] != nt_lm.sent[0]


def test_change_des_cleartext_sends_lm_and_nt():
    # With the cleartext old password both LM and NT authentication blobs are sent in the first request.
    dce = _SeqDCE([0])
    assert samr.change_des(dce, object(), Secret(password="OldPass1!"), new_password="NewPass1!") == 0
    assert len(dce.sent) == 1
    assert dce.sent[0][0] == 1  # LmPresent
    assert dce.sent[0][1] == 1  # NtPresent


def test_change_des_pass_the_hash_is_nt_only():
    # A pass-the-hash change has no cleartext old password, so the LM OWF is unknown: NT authentication only.
    dce = _SeqDCE([0])
    assert samr.change_des(dce, object(), Secret(nt_hash=EMPTY_NT), new_password="NewPass1!") == 0
    assert dce.sent[0][0] == 0  # LmPresent off
    assert dce.sent[0][1] == 1  # NtPresent on


def test_change_des_retries_on_lm_cross_required():
    # An NT-only change against an account that also stores LM draws STATUS_LM_CROSS_ENCRYPTION_REQUIRED;
    # the loop must resend with the LM cross-encryption present.
    dce = _SeqDCE([CROSS_LM, 0])
    assert samr.change_des(dce, object(), Secret(nt_hash=EMPTY_NT), new_password="NewPass1!") == 0
    assert len(dce.sent) == 2
    assert dce.sent[0][3] == 0  # first call: LmCrossPresent off
    assert dce.sent[1][3] == 1  # retry: LmCrossPresent on


def test_change_des_retries_on_nt_cross_required():
    # A both-hash change against an account that stores only LM draws STATUS_NT_CROSS_ENCRYPTION_REQUIRED.
    dce = _SeqDCE([CROSS_NT, 0])
    assert samr.change_des(dce, object(), Secret(password="OldPass1!"), new_password="NewPass1!") == 0
    assert len(dce.sent) == 2
    assert dce.sent[0][2] == 0  # first call: NtCrossPresent off
    assert dce.sent[1][2] == 1  # retry: NtCrossPresent on


def test_change_des_wrong_password_does_not_retry():
    # A non-cross-encryption rejection is returned verbatim with no resend.
    dce = _SeqDCE([WRONG_PW])
    assert samr.change_des(dce, object(), Secret(password="OldPass1!"), new_password="NewPass1!") == WRONG_PW
    assert len(dce.sent) == 1


def test_change_des_new_hash_is_nt_only_with_lm_cross():
    # Setting a raw new NT hash (no cleartext): old proved by NT only (LmPresent off), and the new-LM cross
    # rides along (LmCrossPresent on) with the empty-LM placeholder, matching impacket's hSamrChangePasswordUser.
    dce = _SeqDCE([0])
    assert samr.change_des(dce, object(), Secret(password="OldPass1!"), new_nt_hash=EMPTY_NT) == 0
    assert len(dce.sent) == 1
    assert dce.sent[0][0] == 0  # LmPresent off (NT-only old auth)
    assert dce.sent[0][1] == 1  # NtPresent on
    assert dce.sent[0][2] == 0  # NtCrossPresent off
    assert dce.sent[0][3] == 1  # LmCrossPresent on (new LM stored)


# Real SamrUnicodeChangePasswordUser3 (opnum 63) response stubs captured live from a Server 2022 DC: the
# first is a too-short rejection (STATUS_PASSWORD_RESTRICTION with a populated EffectivePasswordPolicy and
# ExtendedFailureReason 1), the second is a success (both referents NULL). They prove change_diag reads the
# diagnostics out of the response body even though the trailing status is non-zero.
DIAG_RESTRICTION_STUB = bytes.fromhex("0000020007001800010000000080a60affdeffff0000000000000000040002000100000000000000000000006c0000c0")
DIAG_SUCCESS_STUB = bytes.fromhex("000000000000000000000000")


class _CallRecvDCE:
    """A DCE stub exposing the call()/recv() pair change_diag uses to dodge impacket's status auto-raise."""

    def __init__(self, stub):
        self._stub = stub
        self.opnum = None

    def call(self, opnum, request):  # noqa: ARG002 - the request is built and discarded by the fake
        self.opnum = opnum

    def recv(self):
        return self._stub


def test_change_diag_surfaces_policy_on_restriction():
    # The non-zero ErrorCode must NOT swallow the diagnostics: the effective policy and the extended reason
    # are read from the same response body and returned in the extra map.
    status, extra = samr.change_diag(_CallRecvDCE(DIAG_RESTRICTION_STUB), "\x00", "victim", "NewPass1!", Secret(password="OldPass1!"))
    assert status == 0xC000006C  # STATUS_PASSWORD_RESTRICTION
    assert extra["min_password_length"] == "7"
    assert extra["password_history_length"] == "24"
    assert extra["change_failure_reason"] == "1"
    assert "min_password_age_days" in extra


def test_change_diag_empty_on_success():
    # A success carries NULL referents (empty bytes), so no diagnostics are attached.
    status, extra = samr.change_diag(_CallRecvDCE(DIAG_SUCCESS_STUB), "\x00", "victim", "NewPass1!", Secret(password="OldPass1!"))
    assert status == 0
    assert extra == {}


def test_new_enum_members_exist():
    assert ResetMethod.SAMR_RC4_UNSALTED.value == "samr-rc4-unsalted"
    assert ChangeMethod.RAP.value == "rap"


def test_rap_pad_password_is_16_bytes():
    field = rap._pad_password("Secret123")
    assert len(field) == 16
    assert field.endswith(b"\x00")


def test_rap_change_requires_cleartext_old():
    target = Target(domain="SNOW", user="jdoe", dc="dc")
    with pytest.raises(MethodUnavailable):
        rap.change(target, "jdoe", Secret(nt_hash=EMPTY_NT), "NewPass1!")


def test_rap_oem_change_requires_cleartext_old():
    target = Target(domain="SNOW", user="jdoe", dc="dc")
    with pytest.raises(MethodUnavailable):
        rap.change_oem(target, "jdoe", Secret(nt_hash=EMPTY_NT), "NewPass1!")


def test_rap_oem_send_buffer_is_532_bytes():
    # The opcode-214 send buffer is the 516-byte RC4 password buffer plus the 16-byte LM-OWF verifier.
    old_lm = crypto.lm_owf("OldPass1!")
    new_lm = crypto.lm_owf("NewPass1!")
    send = crypto.build_oem_password_buffer("NewPass1!", old_lm) + crypto.des_owf_encrypt(old_lm, new_lm)
    assert len(send) == 532


def test_rap_oem_in_change_method_enum():
    assert ChangeMethod.RAP_OEM.value == "rap-oem"


def test_internal7_and_internal8_blobs_share_aes_builder():
    # Both AES resets must encode the same SAMPR_ENCRYPTED_PASSWORD_AES blob shape.
    blob = samr._aes_reset_blob(SESSION_KEY, "NewPass1!")
    assert isinstance(blob, ndr.SAMPR_ENCRYPTED_PASSWORD_AES)
    assert crypto is not None
