---
title: "Event Analytics Design Brief Summary"
type: source-summary
description: "Summary of a design brief for a streaming event analytics platform: Cloud Run ingestion, Pub/Sub delivery, an idempotent loader, a stateful sessionizer on GKE Autopilot, and day-partitioned BigQuery storage."
status: stable
tags:
  - source/design-brief
  - gcp/architecture
  - architecture/event-driven
sources:
  - id: design-brief
    resource: "/raw/event-analytics-design-brief.md"
    title: "Event Analytics Platform Design Brief"
    author: "team:cloud-platform"
generated:
  by: "knowledge-compiler/1.2.0"
  at: "2026-11-18T00:00:00Z"
corroborates:
  - "[[Event-Driven PubSub Pipelines]]"
  - "[[Idempotent Event Consumer and Dead-Letter Queue]]"
  - "[[Revision Traffic Splitting and Canary Rollback]]"
complements:
  - "[[BigQuery Governance Notes Summary]]"
---

# Event Analytics Design Brief Summary

Distilled from [[raw/event-analytics-design-brief|Event Analytics Platform Design Brief]], a pre-implementation brief written by a cloud platform team.[^design-brief]

## Thesis

Replace a nightly batch copy with a streaming path so that a product event becomes queryable within a minute, and store events in a layout where a query reads only the days it asks for. The brief accepts at-least-once delivery and makes it safe with an idempotency key. It does not try to guarantee exactly-once processing across every hop.[^design-brief]

## Key Takeaways

- **Acknowledge after durability**: The ingest API on [[Cloud Run]] returns success only after [[Cloud PubSub|Pub/Sub]] has accepted the message. The no-loss goal rests on that ordering.
- **One topic, two delivery modes**: A push subscription drives a stateless loader. A pull subscription with ordering keys feeds a stateful sessionizer. See [[Event-Driven PubSub Pipelines]].
- **Idempotency over exactly-once**: The loader deduplicates on `event_id` with a ledger table in [[Cloud SQL for PostgreSQL]], and messages that keep failing move to a dead-letter topic after five attempts. See [[Idempotent Event Consumer and Dead-Letter Queue]].
- **Runtime by workload shape**: Stateless, request-driven components run on Cloud Run. The stateful, backlog-scaled sessionizer runs on [[GKE Autopilot]]. See [[Cloud Run vs GKE Autopilot Decision Matrix]].
- **Storage that prunes**: The events table in [[BigQuery]] is partitioned by day, clustered by tenant and event type, and rejects queries that lack a partition filter. See [[BigQuery Partitioning and Clustering]].
- **No keys anywhere**: Every hop authenticates with an attached or federated identity. See [[Workload Identity Federation]].
- **Staged rollout**: A new revision takes 5, 25, 50, then 100 percent of traffic, and traffic returns to the previous revision if an objective is breached. See [[Revision Traffic Splitting and Canary Rollback]].
- **One trace end to end**: Trace context travels in message attributes from the HTTP request to the warehouse write. See [[OpenTelemetry Trace Propagation Across Services]].

## Component Map

| Component | Runtime | Delivery | Why it runs there |
| :--- | :--- | :--- | :--- |
| Ingest API | [[Cloud Run]] | HTTPS in, publish out | Stateless and bursty; scales to zero overnight |
| Loader | [[Cloud Run]] | Push subscription | One request per message; scales with delivery rate |
| Sessionizer | [[Google Kubernetes Engine|GKE]] in [[GKE Autopilot|Autopilot]] mode | Pull subscription with ordering keys | Holds session state in memory; scales on backlog |
| Event store | [[BigQuery]] | Storage Write API appends | Day partitions, clustered by tenant and event type |
| Deduplication ledger | [[Cloud SQL for PostgreSQL]] | IAM-authenticated SQL connection | Primary key on `event_id` |

## Targets Stated in the Brief

| Goal | Target | Mechanism |
| :--- | :--- | :--- |
| Freshness | 95th percentile under 60 seconds from accepted request to queryable row | Streaming delivery and Storage Write API appends |
| Durability | No loss after a success response | Publish is acknowledged before the API responds |
| Burst tolerance | 5,000 events per second sustained, 10x bursts for up to 15 minutes | The topic buffers while consumers scale out |
| Duplicates | At-least-once delivery, duplicates removable by `event_id` | Ledger lookup plus a deduplicating view |
| Identity | No exported service account keys | Attached and federated identities |
| Traceability | One trace per event | W3C trace context in message attributes |

## How the Loader Stays Idempotent

1. Look up the message's `event_id` in the ledger. If it is there, acknowledge and stop.
2. Append the row to BigQuery.
3. Insert the `event_id` into the ledger.
4. Return a success status, which acknowledges the message.

A crash between steps 2 and 3 can still leave a duplicate row. The brief accepts that window and points exact-count consumers at a view that keeps one row per `event_id`.[^design-brief]

## Open Questions Carried Forward

- **Connection pressure**: Scale-out of the loader multiplies PostgreSQL connections. The brief caps the instance count and keeps pools small.
- **Hot ordering keys**: Publish throughput per ordering key is limited, so one very active session could lag. A load test is pending.
- **Exactly-once delivery**: Would enabling it on the pull subscription remove the need for application-level deduplication in the sessionizer?
- **BigQuery subscription**: Could a subscription that writes directly to BigQuery replace the loader for the raw table?
- **Cloud Run worker pools**: Not evaluated. If they meet the sessionizer's state and scaling needs, the runtime decision should be revisited.

## Where This Source Is Used

- Entities: [[Cloud Run]], [[Google Kubernetes Engine]], [[Cloud PubSub]], [[BigQuery]], [[Cloud SQL for PostgreSQL]]
- Synthesis: [[Google Cloud Serverless Analytics Reference]], [[Production Readiness and Observability Checklist]]
- Companion source: [[BigQuery Governance Notes Summary]] sets the storage rules that this brief assumes.
