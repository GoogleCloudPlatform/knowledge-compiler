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
extends:
  - "[[Google Cloud Serverless Analytics Reference]]"
complements:
  - "[[Workload Identity Federation]]"
  - "[[OpenTelemetry Trace Propagation Across Services]]"
  - "[[Revision Traffic Splitting and Canary Rollback]]"
  - "[[Idempotent Event Consumer and Dead-Letter Queue]]"
  - "[[BigQuery Partition Pruning Check]]"
---

# Production Readiness and Observability Checklist

This checklist is the launch gate for [[Google Cloud Serverless Analytics Reference]]. It unites five controls that are each defined in their own note, and asks for one piece of verifiable evidence per control. The selection follows the operational excellence and reliability pillars of the Well-Architected Framework: define objectives, monitor comprehensively, manage change, and recover automatically.[^waf-operational-excellence][^waf-reliability]

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
| 1 | Keyless identity | No user-managed service account keys exist. Workloads use attached or federated identities, and database logins use IAM authentication.[^iam-wif][^sql-iam-auth] | Empty key inventory and reviewed IAM bindings | [[Workload Identity Federation|Keyless identity]] |
| 2 | End-to-end trace | One synthetic event produces a single trace in Cloud Trace that covers the HTTP request, the publish, the consumer, and the SQL statement.[^cloud-trace-docs] | Link to the trace | [[OpenTelemetry Trace Propagation Across Services|Trace propagation]] |
| 3 | Safe rollout | New revisions start with no traffic and pass a canary gate with a fixed hold at each step, and the rollback command has been exercised. | Record of the last rollback drill | [[Revision Traffic Splitting and Canary Rollback|Canary rollback]] |
| 4 | Duplicate-safe consumers | Delivering the same event twice produces one durable effect. The dead-letter topic has a subscription and an alert.[^pubsub-monitoring] | Replay test result and alert policy | [[Idempotent Event Consumer and Dead-Letter Queue|Idempotent consumer]] |
| 5 | Bounded analytical scans | Event tables require a partition filter, scheduled queries set a scan limit, and recent job history shows no unexpected full scans.[^bq-jobs-view] | Output of the attested computation | [[BigQuery Partition Pruning Check|Pruning check]] |

## Signals to Alert On

| Signal | Source | What it protects |
| :--- | :--- | :--- |
| Error budget consumption | Service-level objective on the [[Cloud Run]] service[^slo-monitoring] | Stops a rollout before users notice |
| Oldest unacknowledged message age | Regional backlog metric on the [[Cloud PubSub|Pub/Sub]] subscription[^pubsub-monitoring] | Shows a consumer that is falling behind |
| Dead-letter message count | Forwarding metric on the same subscription[^pubsub-monitoring] | Surfaces poison messages |
| Connection saturation | Database metrics for [[Cloud SQL for PostgreSQL]] | Catches a consumer or canary that exhausts connections |
| Bytes processed per query | Job history in [[BigQuery]][^bq-jobs-view] | Detects pruning regressions on event tables |

## What the Controls Share

- **Identity comes first**: Trace exporters, publishers, and database clients all authenticate as the workload. When identity is misconfigured the first symptom is often missing telemetry, which looks like an observability fault. Closing [[Workload Identity Federation]] first removes that ambiguity.
- **Idempotency makes rollback safe**: A rollback replays work that was in flight. Without the deduplication keys from [[Idempotent Event Consumer and Dead-Letter Queue]], [[Revision Traffic Splitting and Canary Rollback]] would trade one incident for another.
- **Tracing is the evidence for the other gates**: The revision attribute shows which revision handled a request, repeated process spans show retries, and the SQL comment ties a slow statement to its request. [[OpenTelemetry Trace Propagation Across Services]] is therefore a dependency of the rollout and consumer gates, not an optional extra.
- **Prevention and measurement are different controls**: [[Partition Filter Enforcement Guardrail]] blocks unfiltered queries at query time, while [[BigQuery Partition Pruning Check]] measures what queries actually scanned. The gate asks for both because a required filter can still be too wide.

## Review Cadence

- **Before the first launch**: Pass all five gates and record the evidence.
- **Every release**: Run gates 2 and 3 in the delivery pipeline.
- **Weekly**: Run [[BigQuery Partition Pruning Check]] over the last 7 days of jobs, as the governance notes require, and review the dead-letter subscription.
- **After an incident**: Add the signal that would have caught it, then update this note.

## Source Context

- [[Event Analytics Design Brief Summary]] states the targets behind gates 1 to 4: no exported keys, one trace for each event, a staged rollout, and duplicates removable by `event_id`.
- [[BigQuery Governance Notes Summary]] states the rules behind gate 5 and leaves open whether the pruning check should block a deployment or only report.

## Related Notes

- [[Google Cloud Serverless Analytics Reference]] is the architecture these gates protect.
- [[Cloud Run vs GKE Autopilot Decision Matrix]] explains why the gates do not depend on the runtime.
- [[Event-Driven PubSub Pipelines]] describes the delivery behavior behind gate 4.
- [[Partition Filter Enforcement Guardrail]] is the preventive half of gate 5.
