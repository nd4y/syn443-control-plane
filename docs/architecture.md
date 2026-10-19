# Architecture baseline
Android Kotlin/Compose owns user intent, Android Network generation and the only VpnService.
A separate native host contains one Go runtime and embedded versioned engine modules; the supervisor can terminate only that host after bounded teardown.
The control plane has separately deployable API, worker, frontend and telemetry-ingest; signer is an isolated privileged role.
Initial PostgreSQL/jobs/outbox and object storage do not require Kafka, Kubernetes or separate databases per service.
Device routing continues offline within its signed lease.
The bounded decision evaluator is compiled into the APK. The control plane supplies data and declarative supported policies, not code.
Security and exit eligibility precede stability, energy, speed and measurement confidence.
M0 implements the pure decision/context contract first. No placeholder authentication is exposed as production-ready.
