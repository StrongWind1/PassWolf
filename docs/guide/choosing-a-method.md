# Choosing a method

This page is a decision guide. It picks the right tool first, then the right method within that tool, and explains the transport and channel choices that constrain each method. Wire detail lives in the internals pages, which are linked from each section: [change methods](../internals/change-methods.md) and [reset methods](../internals/reset-methods.md). The full mapping of method to opnum to spec section is in the [method matrix](../methods.md).

## Step 1: pick the tool

passwolf splits the password operation into three tools because change, reset, and read are different operations with different security models. Pick by what you know and what rights you hold, not by what end state you want.

| You have... | You want to... | Tool | Why |
|---|---|---|---|
| the current password or the current NT hash, and no special rights | set a new password the account owner agrees to | [`passwolf change`](change.md) | a change proves the current secret and needs no privilege; it is subject to the full domain password policy |
| reset rights on the target (delegated or admin) | overwrite the password regardless of the old one | [`passwolf reset`](reset.md) | a reset proves nothing about the old secret, bypasses minimum age and history, and requires a caller with reset rights |
| any read access, authenticated or anonymous | read the effective policy and change nothing | [`passwolf policy`](policy.md) | a read mutates nothing; it reports the domain default and a subject's fine-grained (PSO) effective policy |

!!! note "Change versus reset is a hard line"
    A change is policy-bound: minimum length, history, complexity, and minimum age all apply, because the account owner is rotating their own secret. A reset skips minimum age and history and writes whatever the caller supplies, because a privileged operator is overwriting it. Do not reach for `passwolf reset` to dodge a change policy you should satisfy, and do not expect `passwolf change` to work without the current secret.

## Step 2 (passwolf change): pick the method

For `passwolf change` the answer is almost always `auto`, which is the default. Override it only for a specific protocol need: pass-the-hash on a pinned opnum, the Kerberos or LDAP channel, a machine or trust account, or a legacy SMB1 target.

!!! tip "AUTO is the default and the right choice almost always"
    `auto` selects the strongest method the DC accepts (the AES change, SAMR opnum 73) and falls back to RC4 only when AES is genuinely unavailable, never merely for compatibility. On a Server 2025 DC this matters: that DC disables the legacy RC4 SAMR changes, so `auto` is what routes you to the only SAMR change it still accepts.

### passwolf change decision table

| Situation | Method | Why |
|---|---|---|
| any current self-change, you are unsure | `auto` (default) | picks AES where available, RC4 where not; handles Server 2025 automatically |
| Server 2025 DC, pinned | `samr-aes` | Server 2025 accepts only the AES change; `samr-rc4`, `samr-oem`, and `samr-des` are rejected there |
| pass-the-hash with `--target-old-hash` | `samr-aes`, `samr-rc4`, `samr-des` | these accept the NT hash as the current credential; `auto` also works pass-the-hash |
| you want the structured rejection reason | `samr-diag` | SAMR opnum 63 returns the effective policy and the failure reason; Server 2022 and earlier only, Server 2025 refuses it |
| Kerberos-only environment, no SAMR pipe | `kpasswd` | RFC 3244 change protocol over UDP/TCP 464 |
| you have the cleartext old password and want LDAP | `ldap` | unicodePwd delete-then-add over a sealed channel |
| a computer account | `--account machine` (Netlogon) | rotates the machine secret over the Netlogon secure channel |
| an interdomain trust account | `--account trust` (Netlogon) | rotates the trust secret; use the flat NetBIOS name such as `CONTOSO$` |
| a legacy SMB1 target | `rap-oem` | the working legacy RAP change (RC4 OEM buffer); plain `rap` is LM-only and cannot produce an NTLM-usable password |

!!! warning "Server 2025 rejects the legacy SAMR changes"
    `samr-rc4` (opnum 55), `samr-oem` (opnum 54), and `samr-des` (opnum 38) are accepted by Server 2022 but rejected outright by Server 2025, which permits only the AES change (opnum 73). `samr-diag` (opnum 63) is also refused there with `STATUS_ACCESS_DENIED`. If you pin one of these against a 2025 DC, `passwolf change` reports the rejection cleanly; if you leave it on `auto`, it routes around to the AES change.

### Pass-the-hash on passwolf change

A pass-the-hash change supplies `--target-old-hash` instead of `--target-old-password`. It is NT-only by construction: the LM one-way function cannot be recovered from an NT hash, so only the NT-keyed changes work.

| Method | Pass-the-hash capable | Note |
|---|---|---|
| `samr-aes` | yes | the preferred pass-the-hash change |
| `samr-rc4` | yes | legacy RC4 path |
| `samr-des` | yes | hand-built DES OWF cross-encryption, correct on both-stored, NoLMHash, and pass-the-hash changes |
| `samr-oem` | no | needs the cleartext old password; the LM hash cannot be formed from an NT hash |
| `ldap` | no | needs the cleartext old password; the unicodePwd delete value cannot be formed from an NT hash |

### Machine and trust accounts

Computer and interdomain trust secrets are rotated over the Netlogon secure channel, not the SAMR change pipe. Select the account kind with `--account machine` or `--account trust`; the Netlogon methods are then chosen for you.

| Method | Opnum | Spec | Use |
|---|---|---|---|
| `netlogon-aes` | Netlogon 30, `NetrServerPasswordSet2` | [MS-NRPC] 3.5.4.4.6 | AES NL_TRUST_PASSWORD over a sealed channel; a trust uses its flat NetBIOS name such as `CONTOSO$` over the trusted-domain secure channel |
| `netlogon-des` | Netlogon 6, `NetrServerPasswordSet` | [MS-NRPC] 3.5.4.4.7 | DES OWF; still accepted on Server 2025 |

Set the NetBIOS domain name for the channel with `--netbios` if it cannot be derived from the DNS domain.

??? note "The legacy RAP paths (legacy SMB1 only)"
    The RAP changes run over the SMB1 `\PIPE\LANMAN` named pipe and exist only for targets that still speak it. `rap` (opcode 115, cleartext `NetUserPasswordSet2`, [MS-RAP] 2.5.8.1) is LM-only: the legacy gateway derives only the LM one-way function and calls `SamrChangePasswordUser` with `NtPresent=FALSE`, so it can never store an NT hash and the result is not NTLM-usable. `rap-oem` (opcode 214, `SamOEMChangePasswordUser2`, RC4 OEM buffer keyed by the old LM hash) is not LM-only and does not blank NT: the server recomputes and stores a real NT (and LM) hash from the decrypted OEM cleartext, so the new password is NTLM-usable (live-confirmed by secretsdump on Server 2003, XP, and Server 2022). Both complete on Windows NT 4.0 (where `rap-oem` is validated); prefer `rap-oem` because plain `rap` (opcode 115) requires the cleartext to be OEM-uppercased, while the RC4 OEM buffer needs no such handling, and opcode 115 is a no-op on Server 2003/2008 and XP. Use `rap-oem`, never plain `rap`, when you must change a password on a legacy SMB1 host.

## Step 3 (passwolf reset): pick the method

For `passwolf reset` the default is `auto`, which tries every method in turn (kpasswd, ldaps, ldap, then the SAMR ladder of samr-aes, samr-rc4, samr-rc4-unsalted, samr-hash) and takes the first that succeeds. Override it to pin a single channel: a full policy bypass, a known hash, the Kerberos or LDAP channel only, or the DC-local recovery account.

### passwolf reset decision table

| Situation | Method | Why |
|---|---|---|
| a routine privileged reset | `auto` (default) | kpasswd, then ldaps/ldap, then the SAMR ladder (samr-aes → samr-rc4 → samr-rc4-unsalted → samr-hash); takes the first that succeeds |
| you want UserAllInformation wrapped in the AES reset | `--reset-info-class internal8` | AES cleartext reset wrapping UserAllInformation (UserInternal8); the stored result is identical to `samr-aes`, only the wire shape differs (UserInternal8 wraps UserAllInformation), so it is rarely needed |
| you must bypass all policy, or set a known NT hash | `samr-hash` | SAMR opnum 37 + UserInternal1 sets the NT (and optionally LM) OWF directly, with expiry control; opnum 37 and opnum 58 are interchangeable ([MS-SAMR] 3.1.5.6.5: opnum 37 'MUST behave as with a call to SamrSetInformationUser2'), the info class, not the opnum, selects the operation |
| Kerberos-only environment | `kpasswd` | RFC 3244 set protocol, with the target name and realm (version `0xFF80`) |
| you prefer the LDAP channel | `ldap` | single unicodePwd replace over a sealed channel |
| the DC-local recovery account | `--dsrm` | resets the Directory Services Restore Mode (RID 500) password via `SamrSetDSRMPassword`, SAMR opnum 66 |

!!! tip "set-hash reset bypasses policy and can set a known hash"
    `samr-hash` writes the one-way function directly through UserInternal1 ([MS-SAMR] 3.1.5.6.5), so complexity and length policy do not apply and no Kerberos keys are derived from a cleartext. Supply `--target-new-hash NT` to set the NT half, or `--target-new-hash LM:NT` to set both halves. This is the method to use when you already hold a target hash or need a guaranteed policy-free overwrite.

!!! danger "DSRM is a DC-local account, not a directory user"
    `--dsrm` resets the Directory Services Restore Mode recovery password on the DC you connect to (the local RID 500 account), not a domain user. The `--target-user` value is ignored. It runs over the SMB transport only.

??? note "Expiry control"
    `passwolf reset` forces a change at next logon by default (`--expire`). Pass `--no-expire` to leave the new password not expired, which is the right choice for a service account you do not want prompted at next logon.

## Step 4: transport and channel

Two orthogonal choices affect which methods are reachable: the SAMR transport (`--transport`) and, for the LDAP method, sealed 389 versus LDAPS on 636 (`--ldaps`).

### SAMR transport: smb versus tcp

The SAMR methods run over the `\pipe\samr` named pipe on SMB by default (`--transport smb`). Direct TCP to the SAMR endpoint is available with `--transport tcp`, but some reset methods cannot use it.

!!! warning "The cleartext resets require the SMB session key"
    The AES and RC4 cleartext reset info levels encrypt the new password under the SMB session key, so they require the SMB named-pipe transport, not direct TCP. This affects `samr-aes`, `--reset-info-class internal8`, and `samr-rc4` on `passwolf reset`. The `samr-hash` reset (UserInternal1) sets the NT/LM OWF encrypted under the SMB session key ([MS-SAMR] 2.2.6.23) via the DES-ECB-LM transform ([MS-SAMR] 2.2.11.1), so it too requires the SMB named-pipe transport, not direct TCP. The `--dsrm` reset is SMB-only.

| Method group | smb | tcp | Reason |
|---|---|---|---|
| `passwolf change` SAMR changes | yes | yes | the change opcodes do not key on the SMB session key |
| `passwolf reset` cleartext resets (`samr-aes`, `--reset-info-class internal8`, `samr-rc4`) | yes | no | the new password is encrypted under the SMB session key |
| `passwolf reset` `samr-hash` | yes | no | the NT/LM OWF is DES-encrypted under the SMB session key |
| `passwolf reset` `--dsrm` | yes | no | SMB transport only |

### LDAP channel: sealed 389 versus LDAPS 636

The LDAP method defaults to plain 389 with a SASL sign-and-seal bind, which gives a confidential channel without an LDAPS certificate. This is why the LDAP password method works on a DC that has no server certificate installed. Pass `--ldaps` to use LDAPS on 636 instead when you have a certificate and prefer TLS.

!!! note "Sealed 389 needs no certificate"
    Writing `unicodePwd` requires a confidential channel. passwolf gets that with a sealed bind on 389 by default, so you do not need to install or trust an LDAPS certificate. Use `--ldaps` only when you specifically want the TLS transport on 636.

## Where to go next

- [`passwolf change` guide](change.md) for the full change usage and examples.
- [`passwolf reset` guide](reset.md) for the full reset usage and examples.
- [`passwolf policy` guide](policy.md) for reading the effective policy.
- [Change methods internals](../internals/change-methods.md) for the wire detail of each change opnum.
- [Reset methods internals](../internals/reset-methods.md) for the wire detail of each reset info level.
- [Method matrix](../methods.md) for the complete method-to-opnum-to-spec table.
