# Control session reauthentication

The web console can recover from a fresh-MFA requirement while retaining an
unsaved proposal and its exact pending operation in the original tab. Configure
the control BFF's optional `reauthenticationAcr` to the same assurance value as
the control API. The identity provider must issue a verified authentication time,
the configured ACR and an accepted MFA method. Ordinary scoped reads keep the
existing session. This feature grants no additional rights.

Only an authenticated, proof-bound actor with a live object-scoped grant receives
the closed HTTP403 `catalog_reauthentication_required` response. An expired
session, withdrawn grant, foreign object or invalid proof remains an ordinary
denial. The preflight reads metadata and cannot queue, change, approve or sign
configuration. The independent publisher still verifies the original receipt.

The console opens a separate Keycloak window from an explicit button click,
using fresh PKCE, DPoP, state and login cookies, `prompt=login`, `max_age=0` and
the configured ACR. The destination must match the BFF's configured issuer and
callback. The callback requires the original live session cookie, the same
verified issuer/subject and fresh MFA. Logout or expiry during token exchange
wins over the callback. Success rotates only that session's cookie.

Back in the original tab, **Check sign-in** reads the new session capability.
The administrator explicitly retries the pending operation with the same request
ID and body. Neither the callback nor the capability check saves or publishes.
Popup blocking, a rejected callback or an unavailable server leaves the original
tab's edit intact. A real authorization/session denial clears private buffers.
No proposal, token or private key is placed in browser persistent storage.

GitHub Actions must run the named PostgreSQL scope/no-mutation tests, Go
callback/owner/proof/CSRF/logout-race tests and all five required browser recovery
cases. The browser identity page is synthetic; those tests alone do not prove
real Keycloak MFA conformance, a native administration flow or fleet publication.
The configured live deployment needs separate identity-provider acceptance.

Rollback removes the optional BFF configuration and restores its prior executable
and UI assets. There is no schema migration or access-grant change.
