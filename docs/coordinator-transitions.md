# Coordinator transition contract (M0)
The coordinator is a synchronized in-process model, not the complete PROV activation journal.
All six context fields participate in equality. Counters never wrap; exhaustion rejects numeric changes atomically. Explicit Stop always clears desiredOn/activePathId even at exhaustion; Start remains blocked.

| Event | Preconditions | Context mutation | desiredOn | activePathId |
| --- | --- | --- | --- | --- |
| Construct | valid context | none | false | null |
| Start | activationGeneration below max | activationGeneration+1 | true | null |
| Stop | always | activationGeneration+1 when possible, otherwise unchanged at max | false | null |
| NetworkChanged | networkEpoch below max | networkEpoch+1 | unchanged | null |
| EngineChanged | engineGeneration below max | engineGeneration+1 | unchanged | null |
| Activate | valid config/algorithm/hash and activation counter below max | activationGeneration+1 and new revisions/hash | unchanged | null |
| TryApply | desiredOn, exact context and valid path ID | none | unchanged | selected ID |
| Invalid/stale result or invalid transition | failed precondition | none | unchanged | unchanged |

Start/Stop both invalidate all previously queued completions, including after Start -> Stop -> Start.
A late Stop from a queued old command needs command-queue generation checks in the future Android supervisor; this model is not that supervisor.
Activate here only replaces the model's requested context. Engine apply/validation/rollback and durable committed pointers are M1/M2.
Physical network observation and NetworkEpoch generation belong to the future Android Network callback integration, not a client-supplied remote field.


A future Android supervisor must treat unrepresentable physical network/engine events as fail-closed faults, stop the lane and reject completions until a new trusted context is established. The M0 model does not observe physical events itself.
