# Untrusted subscription normalization

This component is part of M3. It does not yet claim persistence, provider fetching,
administration, publication, device download or full M2/M3 acceptance.

## Accepted subset

| Format | Profiles | Preserved transport/security fields |
| --- | --- | --- |
| URI and standard/raw base64 URI lines | HTTP/HTTPS CONNECT, SOCKS4/4a/5, VLESS, SSH | credentials, VLESS UUID/flow/encryption/packet encoding, TLS SNI/ALPN/uTLS/Reality, WS path/Host, gRPC service, XHTTP host/path/mode |
| sing-box JSON `outbounds` | HTTP, SOCKS, VLESS, SSH | explicit bounded outbound allowlist; inline SSH key/passphrase/host keys, TLS inline trust certificates and versions |
| Xray JSON `outbounds` | HTTP, SOCKS, VLESS | exactly one server/user per outbound; explicit TLS/Reality and WS/gRPC/XHTTP mappings |
| Mihomo YAML `proxies` | HTTP, SOCKS5, VLESS, SSH | explicit field mapping including TLS/Reality and WS/gRPC/XHTTP |

Unsupported protocols, unknown outbound/transport/security parameters, external
key/certificate paths, arbitrary dialer options, mux and XHTTP extension/download
settings fail explicitly. No partially imported source is returned. Insecure TLS
is rejected. SSH requires an explicit host key and password or inline private key.
The complete protocol/transport matrix still needs separate native acceptance.

Imported full configurations are profile sources only. Their listeners, DNS,
routing, scripts, external controllers and selector groups never override policy.
Recognized direct/block/DNS/control-group pseudo-profiles are excluded; an import
with no supported real profiles fails. Provider labels do not grant permissions.
The management preview must explain that control metadata was excluded.

## Identity and limits

Profile IDs are HMAC-SHA256 identities scoped to a source and its private random
32-byte salt. Names/order/tags do not participate; actual outbound changes produce
a new candidate identity. A plain password hash is never published as an ID.
Credential rotation without a provider stable-ID mapping therefore requires
normal candidate/dependency review. Exact duplicate identities are ambiguous.

Input and decoded content are capped at10MiB,5000 profiles,24 nested containers,
200000 JSON/YAML values,256 members per object and64KiB per string. URI lines are
capped at8192 bytes. Duplicate JSON keys/query parameters, nonfinite numbers,
multiple YAML documents, aliases/anchors/merge keys and custom YAML tags fail.
The maintained YAML parser is `go.yaml.in/yaml/v3`3.0.6, pinned with Go checksum
database hashes; its license is MIT/Apache-2.0 as distributed by upstream.

The pure promotion assessment quarantines an empty candidate, removal of any
referenced profile, or removal of more than20% of the old IDs. Exactly20% is
allowed when unreferenced. Persistence must bind any operator review to the exact
candidate hash and source revision and cannot approve dangling dependencies.
Explicit provider revocation/expiry is a separate authority and cannot be turned
into an infinite last-known-good cache.

Errors and formatting use fixed redacted codes. Outbounds stay outside ordinary
JSON inventory. Tests include all formats, rename/reorder/source separation,
transport retention, unsafe metadata, malformed shapes, quota boundaries,
quarantine and fuzz inputs. All compilation and tests execute only in Actions.
