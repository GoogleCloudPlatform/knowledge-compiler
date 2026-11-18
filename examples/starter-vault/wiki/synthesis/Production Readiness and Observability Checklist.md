---
title: "Production Readiness and Observability Checklist"
type: synthesis
description: "Five launch gates for the serverless analytics reference: keyless identity, end-to-end tracing, safe rollout, duplicate-safe consumers, and bounded analytical scans."
status: stable
tags:
  - gcp/operations
  - synthesis/production-readiness
  - architecture/observability
sources:
  - id: waf-operational-excellence
    resource: "https://cloud.google.com/architecture/framework/operational-excellence"
    title: "Well-Architected Framework: Operational excellence pillar"
  - id: waf-reliability
    resource: "https://cloud.google.com/architecture/framework/reliability"
    title: "Well-Architected Framework: Reliability pillar"
  - id: iam-wif
    resource: "https://cloud.google.com/iam/docs/workload-identity-federation"
    title: "Workload Identity Federation"
  - id: sql-iam-auth
    resource: "https://cloud.google.com/sql/docs/postgres/iam-authentication"
    title: "IAM authentication"
  - id: cloud-trace-docs
    resource: "https://cloud.google.com/trace/docs"
    title: "Cloud Trace documentation"
  - id: slo-monitoring
    resource: "https://cloud.google.com/stackdriver/docs/solutions/slo-monitoring"
    title: "Concepts in service monitoring"
  - id: pubsub-monitoring
    resource: "https://cloud.google.com/pubsub/docs/monitoring"
    title: "Monitor Pub/Sub in Cloud Monitoring"
  - id: bq-jobs-view
    resource: "https://cloud.google.com/bigquery/docs/information-schema-jobs"
    title: "JOBS view"
generated:
  by: "knowledge-compiler/1.2.0"
  at: "2026-11-18T00:00:00Z"
x-kc-extends:
  - "/wiki/synthesis/Google Cloud Serverless Analytics Reference.md"
x-kc-complements:
  - "/wiki/concepts/Workload Identity Federation.md"
  - "/wiki/patterns/OpenTelemetry Trace Propagation Across Services.md"
  - "/wiki/patterns/Revision Traffic Splitting and Canary Rollback.md"
  - "/wiki/patterns/Idempotent Event Consumer and Dead-Letter Queue.md"
  - "/wiki/concepts/BigQuery Partition Pruning Check.md"
---

# Production Readiness and Observability Checklist

This checklist is the launch gate for [Google Cloud Serverless Analytics Reference](Google%20Cloud%20Serverless%20Analytics%20Reference.md). It unites five controls that are each defined in their own note, and asks for one piece of verifiable evidence per control. The selection follows the operational excellence and reliability pillars of the Well-Architected Framework: define objectives, monitor comprehensively, manage change, and recover automatically.[^waf-operational-excellence][^waf-reliability]

## Gate Order

```mermaid
flowchart LR
  Identity[Keyless identity] --> Trace[End-to-end trace]
  Trace --> Rollout[Safe rollout]
  Rollout --> Consumer[Duplicate-safe consumers]
  Consumer --> Scans[Bounded analytical scans]
  Scans --> Launch([Production launch])
```

The order is deliberate. Telemetry export and database access depend on identity, the rollout gate needs traces as evidence, and the consumer and scan gates are verified by replaying traffic through a release that can be rolled back.

## Launch Gates

| Gate | Control | Pass criteria | Evidence | Owning note |
| :--- | :--- | :--- | :--- | :--- |
| 1 | Keyless identity | No user-managed service account keys exist. Workloads use attached or federated identities, and database logins use IAM authentication.[^iam-wif][^sql-iam-auth] | Empty key inventory and reviewed IAM bindings | [Keyless identity](../concepts/Workload%20Identity%20Federation.md) |
| 2 | End-to-end trace | One synthetic event produces a single trace in Cloud Trace that covers the HTTP request, the publish, the consumer, and the SQL statement.[^cloud-trace-docs] | Link to the trace | [Trace propagation](../patterns/OpenTelemetry%20Trace%20Propagation%20Across%20Services.md) |
| 3 | Safe rollout | New revisions start with no traffic and pass a canary gate with a fixed hold at each step, and the rollback command has been exercised. | Record of the last rollback drill | [Canary rollback](../patterns/Revision%20Traffic%20Splitting%20and%20Canary%20Rollback.md) |
| 4 | Duplicate-safe consumers | Delivering the same event twice produces one durable effect. The dead-letter topic has a subscription and an alert.[^pubsub-monitoring] | Replay test result and alert policy | [Idempotent consumer](../patterns/Idempotent%20Event%20Consumer%20and%20Dead-Letter%20Queue.md) |
| 5 | Bounded analytical scans | Event tables require a partition filter, scheduled queries set a scan limit, and recent job history shows no unexpected full scans.[^bq-jobs-view] | Output of the attested computation | [Pruning check](../concepts/BigQuery%20Partition%20Pruning%20Check.md) |

## Signals to Alert On

| Signal | Source | What it protects |
| :--- | :--- | :--- |
| Error budget consumption | Service-level objective on the [Cloud Run](../entities/Cloud%20Run.md) service[^slo-monitoring] | Stops a rollout before users notice |
| Oldest unacknowledged message age | Regional backlog metric on the [Pub/Sub](../entities/Cloud%20PubSub.md) subscription[^pubsub-monitoring] | Shows a consumer that is falling behind |
| Dead-letter message count | Forwarding metric on the same subscription[^pubsub-monitoring] | Surfaces poison messages |
| Connection saturation | Database metrics for [Cloud SQL for PostgreSQL](../entities/Cloud%20SQL%20for%20PostgreSQL.md) | Catches a consumer or canary that exhausts connections |
| Bytes processed per query | Job history in [BigQuery](../entities/BigQuery.md)[^bq-jobs-view] | Detects pruning regressions on event tables |

## What the Controls Share

- **Identity comes first**: Trace exporters, publishers, and database clients all authenticate as the workload. When identity is misconfigured the first symptom is often missing telemetry, which looks like an observability fault. Closing [Workload Identity Federation](../concepts/Workload%20Identity%20Federation.md) first removes that ambiguity.
- **Idempotency makes rollback safe**: A rollback replays work that was in flight. Without the deduplication keys from [Idempotent Event Consumer and Dead-Letter Queue](../patterns/Idempotent%20Event%20Consumer%20and%20Dead-Letter%20Queue.md), [Revision Traffic Splitting and Canary Rollback](../patterns/Revision%20Traffic%20Splitting%20and%20Canary%20Rollback.md) would trade one incident for another.
- **Tracing is the evidence for the other gates**: The revision attribute shows which revision handled a request, repeated process spans show retries, and the SQL comment ties a slow statement to its request. [OpenTelemetry Trace Propagation Across Services](../patterns/OpenTelemetry%20Trace%20Propagation%20Across%20Services.md) is therefore a dependency of the rollout and consumer gates, not an optional extra.
- **Prevention and measurement are different controls**: [Partition Filter Enforcement Guardrail](../patterns/Partition%20Filter%20Enforcement%20Guardrail.md) blocks unfiltered queries at query time, while [BigQuery Partition Pruning Check](../concepts/BigQuery%20Partition%20Pruning%20Check.md) measures what queries actually scanned. The gate asks for both because a required filter can still be too wide.

## Review Cadence

- **Before the first launch**: Pass all five gates and record the evidence.
- **Every release**: Run gates 2 and 3 in the delivery pipeline.
- **Weekly**: Run [BigQuery Partition Pruning Check](../concepts/BigQuery%20Partition%20Pruning%20Check.md) over the last 7 days of jobs, as the governance notes require, and review the dead-letter subscription.
- **After an incident**: Add the signal that would have caught it, then update this note.

## Source Context

- [Event Analytics Design Brief Summary](../sources/Event%20Analytics%20Design%20Brief%20Summary.md) states the targets behind gates 1 to 4: no exported keys, one trace for each event, a staged rollout, and duplicates removable by `event_id`.
- [BigQuery Governance Notes Summary](../sources/BigQuery%20Governance%20Notes%20Summary.md) states the rules behind gate 5 and leaves open whether the pruning check should block a deployment or only report.

## Related Notes

- [Google Cloud Serverless Analytics Reference](Google%20Cloud%20Serverless%20Analytics%20Reference.md) is the architecture these gates protect.
- [Cloud Run vs GKE Autopilot Decision Matrix](Cloud%20Run%20vs%20GKE%20Autopilot%20Decision%20Matrix.md) explains why the gates do not depend on the runtime.
- [Event-Driven PubSub Pipelines](../concepts/Event-Driven%20PubSub%20Pipelines.md) describes the delivery behavior behind gate 4.
- [Partition Filter Enforcement Guardrail](../patterns/Partition%20Filter%20Enforcement%20Guardrail.md) is the preventive half of gate 5.
