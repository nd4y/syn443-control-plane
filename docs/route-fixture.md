# Temporary LAN route acceptance fixture

`cmd/route-fixture` is a Linux-only, standard-library runtime for a bounded
physical Wi-Fi acceptance session. It is not a general proxy, provisioning
resource, public service or replacement for the normal catalogue approval and
device-configuration APIs. Builds and executable checks belong in GitHub
Actions. Deployment, firewall changes, catalogue approval and the Xperia test
remain separate owner-controlled stages.

The caller creates a private runtime configuration and private catalogue. The
binary never generates or renders profiles, credentials, IP addresses, endpoint
addresses, request paths, nonces, raw errors or logs. There are no default
credentials, sample credentials or command-line bypasses for address checks.

## Closed configuration

Start with `route-fixture -config <owned-runtime-file>`. The file must be owned
by the effective runtime UID, regular, exactly mode `0600`, nonempty and at most
8,192 bytes. Symlinks, FIFOs, directories and a changed file identity between
`Lstat` and `Open` are rejected. The runtime checks the opened inode and bounds
the subsequent read as well. Linux no-follow/nonblocking open flags prevent a
replacement symlink or FIFO from changing that read or blocking Open. Special
setuid/setgid/sticky mode bits are rejected too. Keep the file in private runtime
storage; do not place it in source, an image layer, Actions artifacts or logs.

Every object has exactly the following case-sensitive keys. Duplicate keys,
unknown keys, nulls, arrays, booleans, fractional integer fields and a trailing
JSON value are rejected.

| Object | Required fields |
| --- | --- |
| root | `schemaVersion`, `listenIP`, `expectedPeerIP`, `ingressPorts`, `ttlSeconds`, `branches` |
| `ingressPorts` | integer `a`, integer `b` |
| `branches` | `a`, `b` |
| each branch | `entry`, `exit` |
| each entry/exit | string `username`, string `password` |

`schemaVersion` is exactly `1`. `listenIP` and `expectedPeerIP` are exact
canonical private IPv4 addresses, excluding loopback and unspecified addresses.
The latter is the single physical phone source address, not a subnet or a
forwarded HTTP header. Both ingress ports are distinct integers in
`1024..65535`. `ttlSeconds` is in `30..3600`.

The caller generates fresh entry and exit credentials for each branch at
acceptance runtime. Each username/password is 1..128 printable ASCII bytes,
excluding spaces and control bytes; usernames also exclude `:`. Use separate,
cryptographically random values for all four roles. The caller already knows
them for the private catalogue and does not obtain them from fixture stdout.
Remove the runtime file when the owned acceptance session is finished.

## Fixed topology and protocol

Only the two ingress listeners bind the configured private LAN address. Every
accepted ingress connection must originate from `expectedPeerIP`. Both exits
and the one common proof target bind only IPv4 loopback, on ephemeral ports.
No listener binds a wildcard address.

Internal exit and target accepts require the exact TCP local/remote tuple of a
currently owned derived dial, plus its branch and generation. A successful TCP
handshake may precede Dial returning, so the existing accept loop waits at most
two seconds for the matching registration, with cancellation and bounded
notifications; it creates no extra waiting goroutine. Unknown local clients
cannot use exit credentials to bypass that ownership check. Normal health
checks follow the mapped chain and may connect/close without application data.

| Branch | LAN ingress | Only permitted SOCKS CONNECT destination |
| --- | --- | --- |
| A | configured port `a` | `192.0.2.80:21080` |
| B | configured port `b` | `192.0.2.81:21081` |

Each virtual exit maps only to its own loopback HTTP exit. SOCKS5 requires
RFC1929 authentication, IPv4 ATYP and CONNECT. No-auth, BIND, UDP ASSOCIATE,
domain-name/IPv6 ATYP, a destination belonging to the other branch, and any
other address/port are rejected before dialing. There is no DNS lookup path.

Each HTTP exit accepts only authenticated
`CONNECT 192.0.2.83:44383 HTTP/1.1` with exactly matching `Host` and a single
canonical Basic `Proxy-Authorization` header. Credentials are compared using
fixed-length SHA-256 digests and a constant-time comparison. Headers are bounded
to 8,192 bytes, use strict CRLF framing and reject case-insensitive duplicate
fields, folded fields, unknown fields, Content-Length, Transfer-Encoding and
Trailer. Only Host, Proxy-Authorization, User-Agent, Accept and keep-alive
Connection/Proxy-Connection fields are supported. The exit maps only to the
common owned loopback target. Buffered bytes after CONNECT are preserved through
both relay layers.

The target accepts only `GET /proof/<32 lowercase hex characters> HTTP/1.1`
with the fixed virtual target Host. Its JSON body contains only the nonce
provided in that request. It does not store, generate or log nonces. The owner
must compare the actual response on the phone with a newly generated nonce;
`proofs` counts server response writes and is not delivery or VPN-path proof.
Empty connect-and-close TCP health checks are permitted without sending data.
The fixture provides no TLS, UDP, ICMP, country detection or Internet access.

## Bounds and lifecycle

There are at most **8 active plus reserved accepted-connection permits** across
all five listeners. A permit is acquired before Accept, including for an idle
listener, and for an unauthenticated peer. Therefore idle internal listeners
can reserve capacity, and a saturated TCP connection can remain in the bounded
OS listen backlog until capacity is available. No goroutine is created for a
connection waiting for a permit. The intended load is one nonce flow and one
probe; two complete nonce flows are also covered by the source tests.
This does not promise two indefinitely held tunnels plus another probe at once.
Idle reservations can leave a later internal stage in the TCP backlog until an
earlier flow closes or reaches its fixed 30-second deadline. Physical acceptance
uses short nonce requests and one probe, then closes branch A before proving B.

This is not a claim of eight total OS sockets. At most five owned listener
sockets and at most one derived loopback dial socket per active accepted
handler exist in addition to accepted sockets. There are at most eight active
handlers and at most five accept-loop goroutines. Relays use two joined copy
workers per tunnel. No derived address comes from untrusted wire data.

Every accepted and derived connection gets a fixed 30-second deadline. A tunnel
shares one aggregate payload quota across both directions. The quota reserves
the maximum header and protocol framing first, so framed traffic on each
accepted TCP connection remains below one MiB. Header parsing and target
responses have their smaller independent bounds. Hitting a limit, disabling
a branch or TTL expiry closes the owned sockets; a handler keeps its permit
until both copy workers have actually exited and its connection is closed.

| Signal to the owned fixture process | Result |
| --- | --- |
| `SIGUSR1` | disable branch A |
| `SIGUSR2` | re-enable A on the same address/port |
| `SIGHUP` | toggle B; status reports `b_disabled` or `b_enabled` |
| `SIGWINCH` | print one bounded counter snapshot |
| `SIGTERM`, `SIGINT` | close all owned listeners/connections and join workers |

Disabling a branch closes its LAN ingress, cancels its pending Accept
reservation, closes only its currently owned traffic and joins the old ingress
accept loop. Its loopback exit remains privately bound but rejects connections
while disabled. Re-enabling increments a generation and opens exactly the same
LAN ingress. A late accept or derived dial from an old generation cannot obtain
current ownership. The serial control lock prevents repeated toggles from
accumulating old accept loops. Disabling A does not close B's traffic.

There are at most eight internal dial links, bounded again at registration.
Each link retains the actual dial-connection identity, not just numeric TCP
addresses. The derived connection wrapper removes its link under the ownership
lock before closing its TCP descriptor, including relay, error, cancellation
and explicit Close paths. An accept rechecks that same link identity under the
lock before admission. Late cleanup only removes its own link, so it cannot
erase a replacement after address reuse. A dial's established descriptor stays
open between handshake and registration; an accept without a registration is
never admitted. Old-generation registrations are refused both before/after
dialing and again at accept. Common-target sockets inherit branch ownership as
well, so disabling a branch closes its actual target-side connections too.

TTL expiry closes every listener and connection, joins all accepted handlers and
prevents re-enabling either branch. No process restart is performed. Stdout
contains only fixed event categories and bounded integer/bool counters,
including `activeAccepted` and `reservedAccept`; stderr does not contain raw
configuration or protocol errors. Use a fresh owned session after expiry.

## Evidence and remaining acceptance

`main_test.go` exercises the real TCP protocol over an unexported loopback-only
unit construction seam. This seam is not exposed by the production CLI; the
production configuration parser continues to reject loopback. Synthetic
RFC1918 configuration fixtures are assembled in memory, with no user LAN values.

The owner must run the new actual Go/race tests in Actions, build the exact
Linux artifact there, review its provenance, deploy it through the owned
Portainer path and then verify the physical Xperia flow through the normal
approved catalogue and signed policy. Test A, disable A and prove B, re-enable
A, disable B and prove A again using a fresh nonce for each step. Capture
redacted fixed counters and phone-side path/generation evidence separately.
Source tests and counters alone do not establish that acceptance. Keep LTE
excluded. Remove the owned fixture deployment and private runtime data after
the session, preserving unrelated services, firewall rules and device settings.
