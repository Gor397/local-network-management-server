# Architecture

The control plane is a local modular monolith: FastAPI, PostgreSQL, a bounded database job worker, React/TypeScript, and an HTTPS reverse proxy. A separate .NET 10 Windows Service reconciles signed declarative policies. RouterOS REST uses verified TLS. No cloud services are needed at runtime.

Trust boundaries: browser → authenticated API; agent → certificate proof-of-possession API; backend → explicitly registered router; deployment repository → approved signed manifest → privileged installer; SSH broker → pinned endpoint host key. Policies cannot contain commands. Uploaded executable deployment and interactive SSH are separate, privileged, MFA-gated capabilities.

Device reports are claims, not independent proof. The compliance evaluator owns the check catalog; missing, stale, wrong-version, or wrong-source evidence is UNKNOWN. Network controls require evidence collected by the router connector. A new policy invalidates prior compliance. Developer devices always have UNVERIFIED endpoint state.

Router changes use immutable previews containing before-state hashes, device ownership tags, encrypted snapshots, approval, serialization, readback and a durable outcome. RouterOS is not transactional. Partial failure is ERROR and requires reconciliation; never report success after a transport error. Production writes default off. A lease is not authorization, and gateway filtering is not Layer 2 isolation.

Existing Windows installations start in audit mode. No policy path deletes accounts, formats drives, or shrinks partitions. Storage assessment and backup/migration approval are separate workflows. The installed service uses SYSTEM with administrator/SYSTEM-only files; standard users cannot modify it. Local administrators and offline attackers remain outside that guarantee.

Low Resource Mode uses one API process, one worker, bounded queues/transfers, paginated queries, content-addressed packages, resumable transfer, and shorter telemetry retention. Security deadlines still apply. Events carry revision identifiers rather than full inventory.

See progress.md for the precise implementation and verification ledger. Unimplemented or hardware-unverified controls must never be presented as operational security guarantees.
