# SYN443 - Secure Your Network

Public development repository: **control-plane**.

Control-plane pilot with separate enrollment API, signed-policy publisher worker,
owner administration CLI, PostgreSQL state and a support-chat web/BFF service.
These are tested components, not the complete administration panel or an accepted
production deployment.

- [Android repository](https://github.com/nd4y/syn443-android)
- [Control plane and canonical contracts](https://github.com/nd4y/syn443-control-plane)
- [Technical specification v0.9](docs/spec/TECHNICAL_SPEC_RU.md):292 requirements,98 acceptance scenarios
- [Implementation and acceptance](docs/implementation-status.md), [roadmap](docs/ROADMAP.md)
- [Requirements register](docs/requirements-register.json), [test strategy](docs/TESTING.md)
- [Architecture/security review](docs/spec/ARCHITECTURE_REVIEW_RU.md), [public-data rules](docs/PUBLIC_DATA.md)

M1 remains partial; M2 and chat have scoped pilot implementations. Full M2-M5 and
version1.0/production readiness are not accepted. One Remnawave API resource and
NetBird belong to version1.0 scope; that scope statement is not delivery proof.
Multiple Remnawave, x-ui/3x-ui and Tailscale/ZeroTier are extension contracts only.

See [enrollment](docs/enrollment-pilot.md), [signed policy](docs/managed-policy.md),
[identity lifecycle](docs/identity-lifecycle.md) and [chat](docs/support-chat.md).
Service identities separate API access, publication/signing and owner privileges.
Copyright (c) 2026 SYN443 contributors. All rights reserved pending an explicit product license. Third-party dependencies retain their own licenses; see LICENSE.

All builds run in GitHub Actions. Local/private signing and physical acceptance
are separate from compilation. User/provider configuration, keys, phone backups,
raw diagnostics and private network identifiers never belong in this repository.
Do not run historical build recipes on the operator laptop or against production.
