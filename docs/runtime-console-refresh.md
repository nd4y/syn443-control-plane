# Live runtime card refresh

A physical client could resume and deliver a new SQL observation while an
already open console card kept displaying its older cached report. Local expiry
was correct, but the operator had to press Refresh after every recovery.

The selected device card now reads its runtime view every60 seconds while the
document and device section are visible. No phone timer, producer budget or
telemetry consent changes. No other section is polled and no observation is
created by reading it. Receipt and sample time retain their original meaning;
periodic reads of the same old report eventually display Stale.

There is one current runtime request. Manual refresh shares it, while other
controls remain usable during an automatic read. A15-second request deadline
prevents a lost connection from holding the card indefinitely. Automatic work
pauses outside the visible section, aborts on hiding the document and is fenced
against selection/logout/authority changes. Explicit user-initiated reads may
finish while their section is hidden, but cannot paint another device/session.
Late cancelled requests cannot schedule another poll or overwrite newer data.
An authorization withdrawal clears private buffers through the existing handler.

The existing contrast gate waits for PatternFly's disabled-to-enabled transition
to settle before measuring the interactive button. Its minimum4.5:1 threshold
is unchanged; no replacement disabled styling or framework override is added.

Five mandatory Chromium scenarios use controlled browser and fixture clocks to
check real new-observation updates, immutable old receipt time, local staleness,
empty-to-populated views, hidden/section/auth suspension, single in-flight work,
late responses, timeout and later recovery. The fixture retains an observation
until a separate simulated producer updates it; a read cannot invent a heartbeat.
All72 existing and new browser outcomes and all other required Actions jobs must
pass. All builds and executable suites remain in Actions.

A real browser login also remained busy while its HTTP request never completed.
The shared JSON transport now bounds the complete request and response body to
15 seconds and retains caller cancellation. A timed-out save keeps the exact
pending operation for explicit retry; it is never retried automatically. Three
additional cases cover a stalled initial session, login and an actually committed save whose
response is withheld, including late responses and unchanged idempotency keys.

Acceptance still requires exact artifact hashes, a guarded web-only pilot
rollout and a live authorized card following a real device report. It does not
attest to traffic or close protocol/cellular/energy/endurance gates. Rollback
restores the preceding web executable and compose; no SQL migration is needed.
