# passwolf reset: reset a password

`passwolf reset` overwrites an account's password as a privileged caller. Unlike a change, a reset proves nothing about the old secret: the directory does not verify the previous password, so a reset succeeds even when the old one is unknown, lost, or expired. Because the server treats the operation as an administrative overwrite rather than a self-service change, it also bypasses the minimum password age and the password history check. The trade-off is authority: every reset requires a caller that already holds reset rights on the target. The caller is named with the required `--auth-as-user`; its credential is supplied with `--auth-as-password` or, for a pass-the-hash bind, `--auth-as-hash`, and when you give neither you are prompted for the caller's password at the terminal with no echo.

!!! note "Reset versus change"
    Use `passwolf reset` when you hold reset rights and want to overwrite the secret outright. Use [passwolf change](change.md) when you know the current password and want to rotate it as the account owner. See [choosing a method](choosing-a-method.md) for the decision in full.

## Synopsis

```
passwolf reset --target-domain DOMAIN --target-user USER [--dc DC] --auth-as-user USER [--auth-as-password PASS] (--target-new-password NEWPASS | --target-new-hash [LM:]NT) [options]
```

`--target-user` is required and names the account to reset. `--auth-as-user` is required and names the privileged caller performing the reset. `--target-domain` is required and gives the DNS domain of the target account. `--dc` is optional and defaults to the `--target-domain` value when omitted. The new secret is given with either `--target-new-password` for the cleartext resets or `--target-new-hash` for the set-hash reset; give exactly one, or give neither and you are prompted for the new password at the terminal with no echo. Prompting this way keeps the secret off the command line and out of the process list.

## What a reset bypasses

A reset is an overwrite, not a self-service rotation, so the server does not apply the controls it enforces on a change:

- Minimum password age is not consulted, so you can reset an account that was changed moments ago.
- Password history is not consulted, so the new secret may equal a recent one.
- The set-hash reset additionally bypasses complexity and length policy, because the server stores the supplied one-way function directly without ever seeing cleartext to validate.

The cleartext resets (`samr-aes`, `samr-rc4`, `samr-rc4-unsalted`, and the advanced AES/RC4 info classes) still pass through complexity and length policy, because the DC receives the new password in cleartext inside an encrypted buffer and validates it. Only the set-hash reset skips that validation.

## Options

Every option `passwolf reset` exposes, grouped as in `--help`.

### Target

| Option | Required | Meaning |
| --- | --- | --- |
| `--target-user USER` | Required | The account to reset. |
| `--target-domain DNS` | Required | The DNS domain of the target account. |
| `--dc DC` | Optional | The DC to reach. Defaults to the `--target-domain` value. |

### New secret (required: give one, prompted if you give neither)

| Option | Required | Meaning |
| --- | --- | --- |
| `--target-new-password PASS` | Required: give one (prompted if you give neither) | The new cleartext password, for the cleartext methods. Omit both this and `--target-new-hash` and you are prompted for the new password with no echo. |
| `--target-new-hash [LM:]NT` | Required: give one (prompted if you give neither) | The new NT hash for the set-hash reset. A bare `NT` sets the NT half only; `LM:NT` sets both halves. |

### Privileged caller

`--auth-as-user` is required. The remaining caller options are optional: if you give neither `--auth-as-password` nor `--auth-as-hash`, you are prompted for the caller's password at the terminal with no echo, which keeps it off the command line and out of the process list.

| Option | Required | Meaning |
| --- | --- | --- |
| `--auth-as-user USER` | Required | The caller account that holds reset rights on the target. |
| `--auth-as-password PASS` | Optional | The caller's password. Omit both this and `--auth-as-hash` and you are prompted for the password with no echo. |
| `--auth-as-hash [LM:]NT` | Optional | The caller's NT hash, for a pass-the-hash bind instead of a password. |
| `--auth-as-domain DNS` | Optional | The caller's domain, when it differs from the target domain. Defaults to the `--target-domain` value. |
| `-k`, `--kerberos` | Optional | Bind the privileged `--auth-as-user` caller with Kerberos instead of NTLM. Uses the TGT in `KRB5CCNAME` when that points to a usable ticket cache, otherwise requests one from the `--dc` KDC. |

With `-k` the bind of the privileged caller authenticates over Kerberos rather than NTLM. When the `KRB5CCNAME` environment variable points to a usable ticket cache, the TGT in it is used and the run needs no password at all, so `-k` suppresses the caller-password prompt. Otherwise a TGT is requested from the KDC, which is the `--dc` host, using `--auth-as-password` or `--auth-as-hash`; you may still pass either with `-k` to fetch a fresh ticket. `-k` governs only how the caller binds. It does not touch the value being set: `--target-new-password`/`--target-new-hash` are unaffected and behave exactly as before.

### Method selection

| Option | Required | Meaning |
| --- | --- | --- |
| `--method METHOD` | Optional | The reset method, or `auto` (default). See the method list below. |
| `--transport {smb,tcp}` | Optional | Transport for the SAMR resets (default `smb`). |
| `--ldaps` | Optional | Use LDAPS on 636 for the `ldap` method instead of sealed LDAP on 389. |

### Expiry

| Option | Required | Meaning |
| --- | --- | --- |
| `--expire` | Optional | Force a change at next logon (default). |
| `--no-expire` | Optional | Leave the password as not expired. |

`--expire` and `--no-expire` are mutually exclusive. The flag is honored by the AES, RC4, and set-hash resets.

### DSRM reset (DC-local recovery account)

| Option | Required | Meaning |
| --- | --- | --- |
| `--dsrm` | Optional | Reset the DC-local Directory Services Restore Mode password via `SamrSetDSRMPassword` (opnum 66). SMB transport only, and the `--target-user` value is ignored. |

### Output formatting

| Option | Required | Meaning |
| --- | --- | --- |
| `--format {text,json,pretty}` | Optional | Output format. The default is `pretty`. |
| `-v`, `--verbose` | Optional | Enable debug logging. |

## Reset methods

`--method` accepts one of: `auto`, `samr-aes`, `samr-rc4`, `samr-rc4-unsalted`, `samr-hash`, `kpasswd`, `ldap`. The DSRM reset is selected by the separate `--dsrm` flag, not by `--method`. The AES all-information form (`UserInternal8`) is reachable through the advanced flags below (`--reset-info-class internal8`) rather than as a standard `--method`.

| Method | New secret | What it does |
| --- | --- | --- |
| `auto` (default) | `--target-new-password` or `--target-new-hash` | Tries every method in turn (kpasswd, ldaps, ldap, samr-aes, samr-rc4, samr-rc4-unsalted, samr-hash) and takes the first that succeeds. If only `--target-new-hash` is supplied, AUTO skips the cleartext methods and goes straight to the set-hash reset. |
| `samr-aes` | `--target-new-password` | AES cleartext reset carrying the password only, via `SamrSetInformationUser2` with `UserInternal7` (the smallest AES form). |
| `samr-rc4` | `--target-new-password` | RC4 + MD5-salt cleartext reset, via `SamrSetInformationUser2` with `UserInternal4InformationNew`. |
| `samr-rc4-unsalted` | `--target-new-password` | Legacy unsalted RC4 cleartext reset, via `SamrSetInformationUser2` with `UserInternal4Information`. |
| `samr-hash` | `--target-new-hash` | Set-hash reset: writes the NT (and optionally LM) one-way function directly, via `SamrSetInformationUser` with `UserInternal1`. Full policy bypass. |
| `kpasswd` | `--target-new-password` | Kerberos set protocol (administrative set, distinct from the self-service change). |
| `ldap` | `--target-new-password` | LDAP `unicodePwd` single replace. Use `--ldaps` to run it over 636. |

For `samr-hash`, the info class (`UserInternal1`, level 18) is what makes the operation a hash-set, not the opnum: opnum 37 (`SamrSetInformationUser`) and opnum 58 (`SamrSetInformationUser2`) are interchangeable ([MS-SAMR] 3.1.5.6.5: opnum 37 "MUST behave as with a call to SamrSetInformationUser2"), so the same write also goes out over `SamrSetInformationUser2`. `UserInternal1` is one of two remotely-usable raw-OWF paths; `UserAllInformation` (level 21) can also carry the NT/LM OWF fields, and both were live-confirmed to set the NT hash on Server 2022 and 2025. `samr-hash` uses opnum 37 to mirror the native Windows client, which sends every classic level over 37 and reserves opnum 58 for the newer salted/AES levels.

### Advanced SAMR selection

Two advanced flags expose the exact wire form, overriding `--method`. They let you send any of the eight settable password-bearing `USER_INFORMATION_CLASS` values over either opnum (37 or 58), sixteen combinations in all. This is for testing and for servers that accept only a particular shape; the standard `--method` shortcuts above cover normal use.

| Flag | Values | Meaning |
| --- | --- | --- |
| `--reset-info-class CLASS` | `internal1`, `userall`, `internal4`, `internal5`, `internal4new`, `internal5new`, `internal7`, `internal8` | Send the reset using this exact info class, overriding `--method`. The hash classes (`internal1`, `userall`) take `--target-new-hash`, or a cleartext `--target-new-password` that is hashed locally into its NT OWF; the rest need `--target-new-password`. |
| `--reset-opnum {37,58}` | `37` or `58` (default `58`) | Which opnum carries the reset: `SamrSetInformationUser` (37) or `SamrSetInformationUser2` (58). Only meaningful with `--reset-info-class`. Older DCs may reject the newer (`*new`, `internal7`, `internal8`) classes on opnum 37. |

The eight classes and what each carries:

| `--reset-info-class` | Level | Cipher | Secret | Notes |
| --- | --- | --- | --- | --- |
| `internal1` | 18 | DES (session key) | NT/LM hash | The dedicated set-hash structure (what `samr-hash` sends). |
| `userall` | 21 | DES (session key) | NT/LM hash | Same hash set carried in the all-information block. |
| `internal4` | 23 | RC4 unsalted (session key) | password | What `samr-rc4-unsalted` sends. |
| `internal5` | 24 | RC4 unsalted (session key) | password | Password-only structure; the server maps it onto `internal4`. |
| `internal4new` | 25 | RC4 + MD5 salt (session key) | password | What `samr-rc4` sends. |
| `internal5new` | 26 | RC4 + MD5 salt (session key) | password | Password-only structure; the server maps it onto `internal4new`. |
| `internal7` | 31 | AES (session key) | password | What `samr-aes` sends; the server maps it onto `internal8`. |
| `internal8` | 32 | AES (session key) | password | AES carried in the all-information block. |

Several classes are server-mapped (`internal5`→`internal4`, `internal5new`→`internal4new`, `internal7`→`internal8`, `internal1` into the all-information block), so they produce an identical stored result to their target, only the wire shape differs. See the [SAMR RPC reference](../reference/samr.md#methods-useful-for-resetting-a-password) for the full structure-by-structure breakdown.

!!! note "AUTO order"
    For a cleartext reset, AUTO walks the method list in order (kpasswd, then ldaps (636), then ldap (389), then the SAMR ladder of samr-aes, samr-rc4, samr-rc4-unsalted, samr-hash) and takes the first that succeeds. A `SamrConnect5` preflight skips the AES rung when the DC does not advertise the AES password buffer. samr-hash is the last resort: because it writes the NT OWF directly it still applies when a password policy rejected every cleartext attempt. Run with `-v` to see which rungs were skipped and why; the outcome reports the method that actually ran, not `auto`.

Protocol depth, info levels, and the buffer encryption for each method live in [reset methods internals](../internals/reset-methods.md).

## Cleartext reset versus set-hash reset

These are two different operations with different inputs and different policy behavior.

=== "Cleartext reset (--target-new-password)"

    You supply the new password as cleartext with `--target-new-password`. The tool encrypts it into the SAMR password buffer (AES or RC4) and the DC decrypts it, validates it against complexity and length policy, and stores it. The account ends up with a real password you can hand to the user.

    ```
    passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewPass1!'
    ```

=== "Set-hash reset (--target-new-hash)"

    You supply the NT hash (or `LM:NT`) with `--target-new-hash`. The DC stores the one-way function directly and never sees cleartext, so complexity and length policy do not apply. This is a full policy bypass. Use it to clone a known hash onto an account or to set a value no cleartext maps to under policy.

    ```
    passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-hash 47c4cc3a368a4a0fa79a7bf059b7adba
    ```

!!! warning "The SAMR cleartext and set-hash resets need the SMB transport"
    The AES, RC4, and set-hash SAMR resets use the SMB session key as the buffer encryption key, so they require the SMB named-pipe transport, not direct TCP. With `--transport tcp` there is no session key to derive from, and these methods cannot run.

## Expiry control

By default a reset sets the account to require a change at next logon (`--expire`). Pass `--no-expire` to leave the password marked as not expired, which is the usual choice for service accounts that must keep authenticating with the value you just set.

!!! warning "Set-hash and expiry: Kerberos AES keys"
    A set-hash reset stores the NT one-way function directly and does not regenerate the account's Kerberos AES keys, which are normally derived from the cleartext. Those keys stay stale or absent until a later cleartext set or change (scripts/10). Combined with `--expire` the server is specified to write PasswordExpired = 1 ([MS-SAMR] 2.2.6.1) and therefore pwdLastSet = 0 ([MS-SAMR] 3.1.5.6.4), flagging must-change-at-next-logon (spec-derived; not exercised live, since the live set-hash resets ran with PasswordExpired = 0). The set-hash reset itself was confirmed to return success on both Server 2022 and Server 2025. If a service account must keep authenticating with the value you just set, pass `--no-expire`.

## DSRM recovery reset

`--dsrm` resets the DC-local Directory Services Restore Mode password, the local recovery account on a domain controller, via `SamrSetDSRMPassword` (opnum 66). It is its own selector and overrides `--method`. This operation is served only over the SMB named pipe, so it requires `--transport smb`, and the `--target-user` value is ignored because the DSRM account is fixed and DC-local rather than a directory object. Supply the new value with `--target-new-password`.

```
passwolf reset --target-domain corp.local --target-user dsrm --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewDsrm1!' --dsrm
```

## Worked examples

```
# AUTO reset (kpasswd -> ldaps -> ldap -> SAMR ladder, first that works) as a privileged caller
passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewPass1!'

# Set the NT hash directly: full policy bypass
passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-hash 47c4cc3a368a4a0fa79a7bf059b7adba

# Set both LM and NT halves
passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-hash aad3b435b51404eeaad3b435b51404ee:47c4cc3a368a4a0fa79a7bf059b7adba

# Reset a service account without forcing a change at next logon
passwolf reset --target-domain corp.local --target-user svc --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewPass1!' --no-expire

# Pin the method to the salted RC4 cleartext reset
passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewPass1!' --method samr-rc4

# Advanced: send a specific info class over a specific opnum (here UserInternal8 over opnum 58)
passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewPass1!' --reset-info-class internal8 --reset-opnum 58

# Advanced: set the hash via the all-information block (UserAllInformation) instead of UserInternal1
passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-hash <NTHASH> --reset-info-class userall

# Reset over the Kerberos set protocol
passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewPass1!' --method kpasswd

# Reset via the LDAP unicodePwd replace over LDAPS
passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewPass1!' --method ldap --ldaps

# Pass-the-hash bind for the privileged caller
passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator --auth-as-hash 47c4cc3a368a4a0fa79a7bf059b7adba --target-new-password 'NewPass1!'

# Bind the privileged caller with Kerberos, using the TGT in KRB5CCNAME (no caller password)
passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator -k --target-new-password 'NewPass1!'

# Reset the DC-local DSRM recovery password
passwolf reset --target-domain corp.local --target-user dsrm --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewDsrm1!' --dsrm

# Emit machine-readable JSON instead of the default pretty output
passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewPass1!' --format json
```

## Output

The default output format is `pretty`. Use `--format text` for a plain single-line result or `--format json` for a machine-readable object. See [output formats](output-formats.md) for the shape of each.

!!! tip "Credentials on the command line"
    Passwords and hashes passed on the command line may be visible to other local users via the process list. Prefer a host where that exposure is acceptable, or supply only the user with `--auth-as-user USER` so the bind credential is not echoed in the argument vector when your workflow allows it.

## Exit status

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | A failed or unavailable method. |
| `2` | A usage error. |

## See also

- [Choosing a method](choosing-a-method.md): reset versus change, and which reset method to pin.
- [Output formats](output-formats.md): the pretty, text, and JSON shapes.
- [Reset methods internals](../internals/reset-methods.md): info levels, opnums, and buffer encryption.
- [Method matrix](../methods.md): every method across the three tools at a glance.
