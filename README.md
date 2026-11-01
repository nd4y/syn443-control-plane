# SYN443 - Secure Your Network
Private development repository: **control plane**.

- Android: https://github.com/nd4y/syn443-android
- Control plane and canonical contracts: https://github.com/nd4y/syn443-control-plane
- [Technical specification v0.8](docs/spec/TECHNICAL_SPEC_RU.md)
- [Architecture/security/development review](docs/spec/ARCHITECTURE_REVIEW_RU.md)
- [Roadmap](docs/ROADMAP.md), [test strategy](docs/TESTING.md), [requirements register](docs/requirements-register.json)

This is the beginning of implementation. It is not a usable VPN client/service yet.
All 277 requirements and 90 acceptance scenarios are retained. A documented scenario is not a passed test.
The first deliverable is a reproducible decision/lifecycle core, followed by a physical Android vertical prototype.
The control-plane repository owns versioned cross-platform schemas and synthetic conformance fixtures; Android vendors an immutable hash-locked snapshot.

One Remnawave API resource and NetBird are in version 1.0.
Multiple Remnawave resources, x-ui/3x-ui and Tailscale/ZeroTier are extension contracts only.
Copyright (c) 2026 SYN443 contributors. All rights reserved pending an explicit product license.
Third-party dependencies retain their own licenses.

## M0 prototype
See [implementation status](docs/M0_IMPLEMENTATION.md) for implemented paths and limitations.

Run: go test ./...; go run ./cmd/api. The preview binds127.0.0.1:8080 only; it does not provide VPN/provisioning.

See [CI delivery limitations](docs/CI_DELIVERY.md) for current artifact-quota and private branch-protection constraints.
