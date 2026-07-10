# Proposal: SASL / Kerberos bind support

**Status:** Proposed (not yet implemented)
**Scope owner:** TBD

## Motivation

Today the plugin only performs an LDAP **simple bind**. That:

- excludes Kerberos-only realms,
- forces a service-account **password to live in config**, and
- cannot authenticate against Active Directory deployments where simple bind is
  disabled but NTLM/Kerberos is permitted.

SASL support widens directory compatibility and improves the security posture
(no stored service-account password for Kerberos/cert-based service auth).

`ldap3` already supports the needed mechanisms: `SASL` (GSSAPI, EXTERNAL,
DIGEST-MD5, PLAIN, KERBEROS) and `NTLM`.

## The critical design constraint

**GSSAPI/Kerberos bind uses _ambient_ credentials (a keytab or credential cache) —
it does not take a password.** JupyterHub hands the authenticator the user's
_typed password_. These do not meet in the middle, so SASL splits into two
distinct jobs:

| Connection | Purpose | Mechanisms that fit |
| --- | --- | --- |
| **Service/bind connection** (search-bind lookups) | Authenticate the plugin to the directory | GSSAPI (keytab), EXTERNAL (client cert), NTLM — none need the user password |
| **User verification** (rebind / direct-bind) | Prove the user's typed password | Simple bind (today), or **NTLM** (password-based). **Not** GSSAPI. |

## Phases

### Phase A — SASL for the service connection (recommended first)

Let the **search-bind service connection** authenticate via **GSSAPI**
(keytab/ccache), **EXTERNAL** (TLS client cert), or **NTLM**, instead of
`bind_user_dn` + `bind_user_password`. User password verification stays simple
bind.

- **Value:** removes the service-account password from config; enables Kerberos
  or client-cert service auth for AD/FreeIPA.
- **Effort:** Medium.

### Phase B — NTLM for user authentication (AD, optional)

Verify the **user's** typed password via **NTLM bind** (`domain\user` + password)
instead of simple bind, in both the direct-bind path and the search-bind rebind.

- **Value:** works where AD simple bind is disabled but NTLM is permitted.
- **Effort:** Small–Medium (reuses Phase A plumbing).

### Phase C — Kerberos password verification (defer / separate feature)

Verify the user's typed password by acquiring a TGT from the KDC (`gssapi` /
kinit-style), independent of LDAP.

- **Value:** niche. **Effort:** Large. **Recommendation:** out of scope for the
  first pass.

## Proposed configuration (all opt-in; defaults preserve current behavior)

```python
# service/bind connection mechanism
c.LDAPAuthenticator.bind_authentication = 'simple'   # simple | gssapi | external | ntlm
c.LDAPAuthenticator.bind_sasl_credentials = None     # GSSAPI keytab/authzid if not using ambient ccache

# user verification mechanism
c.LDAPAuthenticator.user_authentication = 'simple'   # simple | ntlm
c.LDAPAuthenticator.ntlm_domain = None               # optional domain prefix for NTLM
```

Defaults of `'simple'` keep the feature fully backward compatible.

## Integration points

- **`ldap_connection()`** — the single real branch: build `ldap3.Connection(...)`
  kwargs conditionally (`authentication=SASL, sasl_mechanism=GSSAPI/EXTERNAL`, or
  `authentication=NTLM`). Everything else flows through unchanged.
- **`_authenticate_search_bind` / `test_auth`** and **`_authenticate_direct_bind`**
  — for Phase B, route the user-verification bind through the chosen mechanism.

## Dependencies

GSSAPI needs the **`gssapi`** Python package, which needs system Kerberos
libraries (`libkrb5-dev` / `krb5-devel`). Ship as an optional extra so the core
install stays dependency-free:

```toml
[project.optional-dependencies]
kerberos = ["gssapi"]
```

`pip install jupyterhub-ldap-authenticator[kerberos]`. NTLM and EXTERNAL need no
extra package.

## Testing strategy

- **Wiring tests (cheap):** monkeypatch `ldap3.Connection`, assert the correct
  `authentication` / `sasl_mechanism` kwargs are passed for each mode. Extends the
  pattern already used in `test_ldap_connection_disables_referrals`.
- **Integration (stretch):** extend the Docker demo with a KDC — a **Samba AD DC**
  container exercises both GSSAPI and NTLM against real AD; an **MIT KDC +
  OpenLDAP/SASL** exercises GSSAPI against OpenLDAP. Expensive; document as a
  manual verification path rather than CI.
- **CI caveat:** GSSAPI cannot be meaningfully unit-tested without a KDC, so CI
  coverage is wiring-level only.

## Risks

- `gssapi` is a system-dependent build (platform-specific, needs krb5 headers) —
  hence the optional extra.
- GSSAPI depends on operational ambient credentials (ccache/keytab,
  `KRB5_CLIENT_KTNAME`, clock skew), not just config.
- ldap3's GSSAPI path has had version-specific quirks; verify against the shipped
  ldap3.
- Real end-to-end testing requires infrastructure not present in CI.

## Effort & recommendation

| Phase | Value | Effort | Verdict |
| --- | --- | --- | --- |
| **A** — service SASL (GSSAPI/EXTERNAL/NTLM) | High | Medium | Do first |
| **B** — NTLM user auth | Medium | Small–Med | Do if AD demand |
| **C** — Kerberos password verify | Low/niche | Large | Defer |

**Recommendation:** implement **Phase A** as the initial deliverable — highest
leverage (removes the stored service password, unlocks Kerberos/cert service
auth), backward compatible, and testable at the wiring level. Ship B and C as
demand-driven follow-ups.
