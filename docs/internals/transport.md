# Transport and channels

This page describes how passwolf reaches a domain controller: the DCE/RPC channel abstraction in `src/passwolf/transport.py`, the bind identity that authenticates each channel, and the four other wire paths the tools use directly (LDAP, Kerberos kpasswd, the Netlogon secure channel, and the SMB read of SYSVOL). It states which tools and methods ride which transport, and which methods are SMB-only. For what travels inside these channels, see [crypto.md](crypto.md); for how each method is dispatched, see [change-methods.md](change-methods.md), [reset-methods.md](reset-methods.md), and [policy-methods.md](policy-methods.md).

## The DCE/RPC channel

SAMR and LSA are DCE/RPC interfaces. Both can ride one of two protocol sequences: an SMB named pipe (`ncacn_np`) or direct TCP (`ncacn_ip_tcp`). `transport.py` exposes a single `open_channel` entry point and a small `Channel` record that holds the bound `DCERPC_v5` object plus the SMB session key when the transport provides one.

```python
@dataclass
class Channel:
    dce: DCERPC_v5
    session_key: bytes | None
```

The two protocol sequences are selected by `TransportKind` (`src/passwolf/model.py`), which is the value behind the `--transport {smb,tcp}` option on `passwolf change`, `passwolf reset`, and `passwolf policy`:

| `TransportKind` | Wire | Endpoint | SMB session key |
| --- | --- | --- | --- |
| `smb` (default) | `ncacn_np` over an SMB named pipe | TCP 445 | yes, captured at bind |
| `tcp` | `ncacn_ip_tcp`, endpoint-mapper resolved | resolved per interface | no |

For the SMB path, `open_channel` builds an `SMBTransport` to the named pipe (`\samr` for SAMR, `\lsarpc` for LSA), connects, and reads the session key off the live SMB connection with `rpc.get_smb_connection().getSessionKey()`. For the TCP path it resolves the interface endpoint through the endpoint mapper (`epm.hept_map(..., protocol="ncacn_ip_tcp")`), connects, and records `session_key=None`. Both paths optionally raise the auth level to `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` when the caller passes `seal=True`, then bind the interface UUID.

!!! note "Why the session key only exists over SMB"
    The SMB session key is a property of the SMB session, established when the named pipe is opened. Direct TCP has no SMB session and therefore no session key. The reset paths use that key as a content-encryption key (see below), so they are unavailable over TCP and the code surfaces that as a clear `MethodUnavailable` rather than failing obscurely.

### Bind identity: password, pass-the-hash, or Kerberos

The principal that authenticates the bind is modeled by `BindIdentity`. It carries a user, a domain, either a cleartext password or an NT hash, and a flag selecting Kerberos over NTLM:

```python
@dataclass(frozen=True)
class BindIdentity:
    user: str
    domain: str
    password: str = ""
    nt_hash: bytes | None = None
    use_kerberos: bool = False
```

`open_channel` renders the NT hash to the hex form impacket's credential setters expect and passes it through `set_credentials` (TCP) or the `nthash=` argument of `SMBTransport` (SMB). A non-empty hex hash drives a pass-the-hash bind; an empty one drives a password bind. The identity that authenticates the channel is not necessarily the account being changed:

- On `passwolf change`, the bind defaults to the target account itself (it proves its own current secret), unless `--auth-as-user USER` (with `--auth-as-password PASS`) names a different principal for the SAMR or LDAP session. `-k`/`--kerberos` makes that bind use Kerberos.
- On `passwolf reset`, the bind is always the privileged caller named with `--auth-as-user` (and optionally `--auth-as-hash` for a pass-the-hash bind), never the account being reset. `-k`/`--kerberos` makes that bind use Kerberos.
- On `passwolf policy`, the bind is the principal from `--auth-as-user`/`--auth-as-password` or `--auth-as-hash`, or an empty identity when `--anonymous` requests a null-session bind. `-k`/`--kerberos` makes that bind use Kerberos.

#### Kerberos binds

The `-k`/`--kerberos` option on `passwolf change`, `passwolf reset`, and `passwolf policy` sets `use_kerberos` on the `BindIdentity`. When it is set the bind authenticates with Kerberos instead of NTLM: an existing ticket cache named by `KRB5CCNAME` is used when present, so no password is needed, and otherwise a TGT is fetched from the KDC (the `--dc` host) using the password or NT hash already on the identity. Because a populated cache makes the secret optional, the interactive bind-password prompt is suppressed under `-k`.

How each transport implements the Kerberos bind differs, because impacket exposes the ticket cache at different layers:

- **SMB (`ncacn_np`)**: `open_channel` passes `doKerberos=True, kdcHost=target.dc` to impacket's `SMBTransport`. The transport's own `kerberosLogin` then runs with `useCache=True`, and that is the call that reads `KRB5CCNAME`.
- **LDAP (`ldap.py` `_connect`, `policy.py` `_ldap_connect`) and the SYSVOL SMB session (`policy.py` `_sysvol_connect`)**: the bind calls `connection.kerberosLogin(...)` with `useCache=True`, supplied through the shared keyword set built by `transport.kerberos_login_args(identity, kdc_host)`. This connection-level `kerberosLogin` likewise reads `KRB5CCNAME` itself.
- **Direct TCP (`ncacn_ip_tcp`)**: impacket's DCE/RPC bind does not consult `KRB5CCNAME` on its own, so `open_channel` resolves the ticket explicitly with `CCache.parseFile(...)`, hands the resulting TGT/TGS to `set_credentials`, and binds with `RPC_C_AUTHN_GSS_NEGOTIATE` at `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` (a Kerberos bind needs an auth level above NONE). The password or NT hash stays as the fallback used to fetch a TGT when the cache is empty.

#### Expired-password null-session retry

`passwolf change` opens its SAMR channel through `change.py` `_open_samr_channel`, which binds as the configured identity (normally the target proving its own secret). When the account's password is expired, that authenticated bind fails before any change is attempted: the DC returns `STATUS_PASSWORD_MUST_CHANGE` (0xC0000224) or `STATUS_PASSWORD_EXPIRED` (0xC0000071). On either of those two statuses `_open_samr_channel` retries the bind with an anonymous/null `BindIdentity` (`user="", domain="", password=""`) and proceeds over the null session.

This works because the buffer-based SAMR changes (opnums 55, 73, 54, 63) carry the old-secret proof inside the request body, so the server accepts them over a null session ([MS-SAMR] 3.1.5.10.3) even though the bind itself is unauthenticated. It applies to the buffer-based methods only. The handle-based DES change (opnum 38, `samr-des`) cannot use it: a null session is denied the user handle that change operates on, so an expired account combined with `--method samr-des` is reported as unavailable rather than retried.

A bind failure with any other status is not an expiry case, so it is re-raised unchanged. Those failures are now surfaced cleanly: the SMB `SessionError` (a base `Exception`) is caught in `change.py` `main` and logged as an authentication failure, instead of escaping as an uncaught traceback. `STATUS_PASSWORD_MUST_CHANGE` was added to `nterror.py` for the status match.

## Where the SMB session key is consumed

The cleartext SAMR resets encrypt the new password under the SMB session key, so they require the named pipe. Each helper in `src/passwolf/samr.py` checks `session_key is None` first and raises `MethodUnavailable` when the channel is TCP. All SAMR resets ride opnum 58 or its identical sibling opnum 37 ([MS-SAMR] 3.1.5.6.5: opnum 37 'MUST behave as with a call to SamrSetInformationUser2'), the info class choosing the cipher and session-key usage, not the opnum (see [reset-methods.md](reset-methods.md)). The key is used three different ways depending on the info level:

| Reset method (`--method`) | SAMR call / info level | How the session key is used |
| --- | --- | --- |
| `samr-aes` | `SamrSetInformationUser2` + UserInternal7 (31) | the 16-byte session key is the AEAD content-encryption key directly, per [MS-SAMR] 3.1.5.6.4 |
| `--reset-info-class internal8` | `SamrSetInformationUser2` + UserInternal8 (32) | same direct AEAD key, wrapping UserAllInformation |
| `samr-rc4` | `SamrSetInformationUser2` + UserInternal4InformationNew (25) | RC4 key is `MD5(salt + session key)` |
| `samr-hash` | `SamrSetInformationUser` (opnum 37) + UserInternal1 (18) | each OWF half is DES-encrypted under the session key, per [MS-SAMR] 2.2.11.1.1 |

The DSRM reset (`passwolf reset --dsrm`, `SamrSetDSRMPassword`, opnum 66) is also served only over the named pipe: the server refuses a direct-TCP binding, so `passwolf reset` checks `channel.session_key is None` and reports that `--transport smb` is required.

!!! warning "These reset methods are SMB-only"
    `samr-aes`, `--reset-info-class internal8`, `samr-rc4`, `samr-rc4-unsalted`, `samr-hash`, and the `--dsrm` reset all need the named pipe. Pinning `--transport tcp` on any of them yields a `MethodUnavailable` result. AUTO on `passwolf reset` runs over SMB by default, so this only bites a caller who pins TCP explicitly.

By contrast, the SAMR change paths that do not consume the session key (the AES change opnum 73, the RC4/OEM/DES changes, and the opnum-63 diagnostic change) work over either transport. They authenticate the change by proving the old secret in the request body rather than by encrypting under the session key, so TCP is a valid transport for them.

??? note "lsa.py is an internal, unwired module"
    `src/passwolf/lsa.py` (`LsarSetSecret2` opnum 138 AES, `LsarSetSecret` opnum 29 DES) is an internal library not currently wired to any `passwolf reset`/`passwolf change` dispatch; trust-account rotation ships only over the Netlogon secure channel (`passwolf change --account trust`). If the LSA trust reset is ever exposed it would also encrypt the secret value under the SMB session key, making it a named-pipe operation.

## LDAP transport

The LDAP change and reset (`src/passwolf/ldap.py`) and every `ldap-*` policy read (`src/passwolf/policy.py`) write or read `unicodePwd`, which the DC accepts only over a confidential channel. passwolf gives that confidentiality two ways:

=== "Sealed LDAP on 389 (default)"
    The connection uses the `ldap://` scheme and impacket's `LDAPConnection.login`, which performs an SASL sign-and-seal bind (SPNEGO/GSS-API). This seals the channel on the standard LDAP port and needs no server certificate. This is the default for the LDAP method on `passwolf change`, `passwolf reset`, and `passwolf policy`.

=== "LDAPS on 636 (--ldaps)"
    Passing `--ldaps` switches the scheme to `ldaps://`, which uses TLS on port 636 and depends on the DC presenting a valid certificate.

!!! tip "Sealed 389 is the default on purpose"
    Defaulting to sealed LDAP on 389 with no certificate requirement is the deliberate correctness fix over impacket's `changepasswd.py`, which hardcodes `ldaps://` and fails wherever LDAPS is not configured. Reach for `--ldaps` only when you specifically want TLS on 636.

The LDAP `unicodePwd` change is a delete-old plus add-new Modify and so needs the cleartext old password; the LDAP reset is a single replace Modify and needs no old secret. Both bind with the same `BindIdentity` machinery (password or pass-the-hash) used elsewhere.

## Kerberos kpasswd transport

The `kpasswd` change and reset (`src/passwolf/kpasswd.py`) use the Kerberos change-password protocol (RFC 3244, [MS-KILE] 3.1.5.12) on UDP/TCP port 464. Both the change and the set/reset are sent with framing protocol version `0xFF80`; the change carries no `targname`/`targrealm` inside the encrypted `ChangePasswdData` and authenticates as the target to prove the current secret, while the set/reset carries both target fields and authenticates as a privileged caller naming the target. The version field does not distinguish them (impacket sends `0xFF80` for both); `0x0001` appears only in the server's reply. impacket implements both at the protocol layer (`kpasswd.changePassword` / `kpasswd.setPassword`), and passwolf points them at the DC as both the KDC host and the kpasswd host.

`passwolf policy`'s `kpasswd` read does not change anything: it sends a change request with a probe password, expects the DC to reject it with a SOFTERROR, and harvests the password policy carried in that SOFTERROR blob. That probe also rides port 464 (`ik.KRB5_KPASSWD_PORT`). The kpasswd path does not use the SMB session key and is not SMB-only.

## Netlogon secure channel

Machine and trust account changes (`passwolf change --account machine` or `--account trust`) do not use `open_channel`. They run through `src/passwolf/netlogon.py`, which builds a dedicated Netlogon secure channel over `ncacn_ip_tcp` (endpoint-mapper resolved) and authenticates it with the account's own NT hash:

1. `NetrServerReqChallenge` exchanges client and server challenges. passwolf sends the fixed 8-byte client challenge `b"passwolf"`.
2. The session key is computed from the two challenges and the account's NT hash (`ComputeSessionKeyAES`). This is the Netlogon session key, distinct from the SMB session key above.
3. `NetrServerAuthenticate3` proves knowledge of the key with a client credential and negotiates the AES flag.
4. The bound channel is then upgraded to a sealed channel: auth type `RPC_C_AUTHN_NETLOGON`, auth level `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`, AES on, alter-bind to send the `NL_AUTH_MESSAGE`, and `set_session_key`.

The seal step is mandatory against modern DCs: it is the post-CVE-2020-1472 hardening that requires the Netlogon channel to sign and seal. Over that sealed channel passwolf writes the new secret two ways: `netlogon-aes` (`NetrServerPasswordSet2`, opnum 30, an AES-CFB8 `NL_TRUST_PASSWORD` buffer) and `netlogon-des` (`NetrServerPasswordSet`, opnum 6, a DES-encrypted NT OWF). Trust accounts are addressed by their flat NetBIOS name plus `$` over `TrustedDomainSecureChannel`; the `--netbios NAME` option supplies the NetBIOS domain name used in the channel bootstrap when it cannot be derived from the DNS domain.

!!! note "Two different session keys"
    Do not conflate the SMB session key (used by the SAMR cleartext resets) with the Netlogon session key (used to seal the Netlogon channel and encrypt the machine/trust password buffer). They are computed differently and used by different methods. See [crypto.md](crypto.md) for both derivations.

## SYSVOL read over SMB

The `sysvol` policy method (`passwolf policy --method sysvol`, in `src/passwolf/policy.py`) reads the configured password and lockout intent from the GPO security templates. It opens an authenticated `SMBConnection` to the DC, lists the GPO GUID directories under the `SYSVOL` share (`<domain>\Policies\*`), and fetches each GPO's `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` over SMB, parsing the `[System Access]` block per [MS-GPSB] 2.2.1 (password-policy keys per 2.2.1.1). This is a file read over the SMB share, not a DCE/RPC named pipe, so it does not use `open_channel` and does not consume an RPC session key. It uses the same `BindIdentity` for authentication and is naturally SMB-only.

## RAP over SMB1

The legacy `rap` and `rap-oem` changes on `passwolf change` (`src/passwolf/rap.py`) ride a different transport again: `\PIPE\LANMAN` over SMB1, using a raw `SMB_COM_TRANSACTION`. The documented `rap` change (`NetUserPasswordSet2`, opcode 115) is supported on Windows 2000 Server, Server 2003, and Server 2008 per [MS-RAP] note <43>; the `rap-oem` opcode-214 OEM change is undocumented. Both ride SMB1, so they reach only legacy SMB1 Windows; modern DCs remove SMB1 and the gateway is unreachable, so these methods report unavailability there. In the lab only NT 4.0 actually completed the change; Server 2003/2008 and XP returned a no-op (`ERROR_UNEXP_NET_ERR` 0x003B). These ride SMB1, so they reach the host over either the NetBIOS session service (TCP 139) or direct SMB (TCP 445), whichever the legacy host exposes; the one host where the change actually completed (NT 4.0) was reached over TCP 139 because it has no 445, while the three hosts that do expose 445 (XP, Server 2003, Server 2008) are exactly the ones that returned the no-op. They force the SMB1 dialect and are not subject to the `--transport` option (which only selects between `ncacn_np` and `ncacn_ip_tcp` for the SAMR interface).

## Transport at a glance

| Method | Tool(s) | Transport | Port | Session key needed | SMB-only |
| --- | --- | --- | --- | --- | --- |
| `samr-aes`, `samr-rc4`, `samr-oem`, `samr-des`, `samr-diag` (change) | passwolf change | DCE/RPC `\samr` (`smb`) or `ncacn_ip_tcp` (`tcp`) | 445 / mapped | no | no |
| `samr-aes`, `--reset-info-class internal8`, `samr-rc4`, `samr-rc4-unsalted`, `samr-hash` (reset) | passwolf reset | DCE/RPC `\samr` named pipe | 445 | yes (SMB) | yes |
| `--dsrm` reset (opnum 66) | passwolf reset | DCE/RPC `\samr` named pipe | 445 | yes (SMB) | yes |
| `samr-query`, `samr-getdompwinfo`, `samr-getusrpwinfo`, `samr-diag` (read) | passwolf policy | DCE/RPC `\samr` (`smb`) or `ncacn_ip_tcp` (`tcp`) | 445 / mapped | no | no |
| `ldap` / `ldap-*` | passwolf change, passwolf reset, passwolf policy | sealed LDAP 389, or LDAPS 636 with `--ldaps` | 389 / 636 | no | no |
| `kpasswd` | passwolf change, passwolf reset, passwolf policy | Kerberos change/set protocol | 464 | no | no |
| `netlogon-aes`, `netlogon-des` | passwolf change (`--account machine`/`trust`) | sealed Netlogon `ncacn_ip_tcp` | mapped | Netlogon key | no |
| `sysvol` | passwolf policy | SMB share file read | 445 | no | yes |
| `rap`, `rap-oem` | passwolf change | `\PIPE\LANMAN` over SMB1 | 139 / 445 (SMB1) | no | yes (SMB1) |

Output for all three tools defaults to the `pretty` format; `--format {text,json,pretty}` selects otherwise. See [crypto.md](crypto.md) for the buffer and key derivations these transports carry, and [change-methods.md](change-methods.md), [reset-methods.md](reset-methods.md), and [policy-methods.md](policy-methods.md) for the per-method dispatch.
