# Architectural Patterns

OKF v0.3 subdirectory index for `wiki/patterns/` (see [Master Index](../../index.md) and [Wiki Index](../index.md)).

- [Idempotent Event Consumer and Dead-Letter Queue](Idempotent%20Event%20Consumer%20and%20Dead-Letter%20Queue.md): Pair a deduplication key with a dead-letter topic so at-least-once Pub/Sub delivery produces exactly one durable effect in Cloud SQL for PostgreSQL or BigQuery.
- [OpenTelemetry Trace Propagation Across Services](OpenTelemetry%20Trace%20Propagation%20Across%20Services.md): Carry one W3C traceparent context from the first HTTP request through Cloud Run, across Pub/Sub, and into Cloud SQL for PostgreSQL so a single trace shows the whole path of an event.
- [Partition Filter Enforcement Guardrail](Partition%20Filter%20Enforcement%20Guardrail.md): Set require_partition_filter on large partitioned BigQuery tables so the engine rejects any query that cannot prune partitions.
- [Revision Traffic Splitting and Canary Rollback](Revision%20Traffic%20Splitting%20and%20Canary%20Rollback.md): Release each Cloud Run revision with no traffic, shift requests to it in small steps, and return to the last good revision when health signals leave the service-level objective.
