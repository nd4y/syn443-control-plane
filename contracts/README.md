# Decision contract 0.1.0
M0 contract, not the complete provisioning wire protocol. Normative schema and shared vectors live here.
All fields are required; unknown properties/versions fail closed. Integers have schema bounds; no floating point.
Context equality includes all six fields. Timestamps are in the same monotonic epoch and never wall-clock guessed.
A candidate is rejected, in order, for context mismatch, disallowed policy, wrong exit, required check failure, hard failure or stale/future evidence.
Evidence expires at age >= TTL. Duplicate IDs and inconsistent sample aggregates invalidate the request.
Rank is lexicographic: stability, energy, latency band, confidence, ASCII path ID.
Stability: optional-degraded=2; else stable=0 if >=5 samples, >=3 trailing successes and failures*100<=samples*5; otherwise provisional=1.
Aggregates describe at most the last20 results within10 minutes and must be measured on the requested complete path. M0 does not collect network evidence yet.
Energy: worst of bytes/min (<=2048/<=8192/above), handshakes/min (<=1/<=4/above), active backups (<=1/<=2/above); unknown=high2.
Latency: floor(ms/25), unknown or incomparable metric group=24001. Max supported latency600000ms. Units and target group must match.
Confidence: samples>=10 =>0, samples>=5 =>1, otherwise2. It never overrides higher-priority classes.
All rejected records and candidate ties are ordered by ASCII ID, independent of input order. Empty eligible set means selectedPathId=null, never Online.
No hysteresis, real graph enumeration, signed policy, identity or network probing is claimed by this version.
Coordinator model: Start/Stop/NetworkChanged/Activate/EngineChanged increment relevant generations and clear prior selections.
Stop wins later completion; comparison/commit is synchronized. Overflow rejects before mutation; no counter wraps.

The implemented preview API is specified in v1/openapi.json and its result schema. In-process transitions are specified in ../docs/coordinator-transitions.md. All transport and schema limits apply together.
