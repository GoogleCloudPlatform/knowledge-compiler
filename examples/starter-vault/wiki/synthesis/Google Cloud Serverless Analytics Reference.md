---
title: "Google Cloud Serverless Analytics Reference"
type: synthesis
description: "Reference architecture combining Cloud Run ingestion and loading, Pub/Sub delivery, a stateful GKE Autopilot consumer, a Cloud SQL for PostgreSQL deduplication ledger, and partitioned BigQuery analytics."
status: stable
tags:
  - gcp/architecture
  - synthesis/serverless
  - architecture/event-driven
sources:
  - id: gcp-arch-center
    resource: "https://cloud.google.com/architecture"
    title: "Cloud Architecture Center"
  - id: gke-and-cloud-run
    resource: "https://cloud.google.com/kubernetes-engine/docs/concepts/gke-and-cloud-run"
    title: "GKE and Cloud Run"
  - id: pubsub-subscriptions
    resource: "https://cloud.google.com/pubsub/docs/subscription-overview"
    title: "Subscription overview"
  - id: pubsub-bigquery-subscriptions
    resource: "https://cloud.google.com/pubsub/docs/bigquery"
    title: "BigQuery subscriptions"
  - id: bq-partitioned-tables
    resource: "https://cloud.google.com/bigquery/docs/partitioned-tables"
    title: "Introduction to partitioned tables"
generated:
  by: "knowledge-compiler/1.2.0"
  at: "2026-11-18T00:00:00Z"
x-kc-complements:
  - "/wiki/concepts/Cloud Run Serverless Containers.md"
  - "/wiki/concepts/GKE Autopilot.md"
  - "/wiki/concepts/BigQuery Partitioning and Clustering.md"
  - "/wiki/concepts/BigQuery Partition Pruning Check.md"
  - "/wiki/concepts/Event-Driven PubSub Pipelines.md"
---

# Google Cloud Serverless Analytics Reference

This synthesis connects stateless ingestion on [Cloud Run](../entities/Cloud%20Run.md), asynchronous delivery through [Pub/Sub](../entities/Cloud%20PubSub.md), stateful processing on [Google Kubernetes Engine](../entities/Google%20Kubernetes%20Engine.md), a deduplication ledger in [Cloud SQL for PostgreSQL](../entities/Cloud%20SQL%20for%20PostgreSQL.md), and partitioned analytics in [BigQuery](../entities/BigQuery.md) into one composable reference pattern.[^gcp-arch-center] It generalizes the platform described in [Event Analytics Design Brief Summary](../sources/Event%20Analytics%20Design%20Brief%20Summary.md) and the table rules in [BigQuery Governance Notes Summary](../sources/BigQuery%20Governance%20Notes%20Summary.md).

## End-to-End Sequence

```mermaid
sequenceDiagram
  autonumber
  participant Client as Client
  participant Ingest as Cloud Run ingest API
  participant Topic as Pub/Sub topic
  participant Loader as Cloud Run loader
  participant SQL as Cloud SQL ledger
  participant BQ as BigQuery
  participant GKE as GKE sessionizer
  Client->>Ingest: POST /events with traceparent
  Ingest->>Topic: Publish with event_id
  Ingest-->>Client: Success after publish is acknowledged
  Topic->>Loader: Push delivery
  Loader->>SQL: Look up event_id
  Loader->>BQ: Append row to analytics.events
  Loader->>SQL: Insert event_id
  Loader-->>Topic: Success response acknowledges
  Topic->>GKE: Streaming pull with ordering keys
  GKE->>BQ: Write closed sessions
  Note over Topic,Loader: Five failed deliveries go to a dead-letter topic
```

## Component Roles

| Layer | Service | Role in the flow | Governing notes |
| :--- | :--- | :--- | :--- |
| Ingestion edge | [Cloud Run](../entities/Cloud%20Run.md) | Validates each event, publishes it, and reports success only after the publish is acknowledged | [Serverless containers](../concepts/Cloud%20Run%20Serverless%20Containers.md), [Canary rollback](../patterns/Revision%20Traffic%20Splitting%20and%20Canary%20Rollback.md) |
| Event backbone | [Pub/Sub](../entities/Cloud%20PubSub.md) | Buffers events and delivers them at least once to a push and a pull subscription[^pubsub-subscriptions] | [Pub/Sub pipelines](../concepts/Event-Driven%20PubSub%20Pipelines.md), [Idempotent consumer](../patterns/Idempotent%20Event%20Consumer%20and%20Dead-Letter%20Queue.md) |
| Stateless loading | [Cloud Run](../entities/Cloud%20Run.md) | Turns each pushed message into one appended row | [Idempotent consumer](../patterns/Idempotent%20Event%20Consumer%20and%20Dead-Letter%20Queue.md), [Trace propagation](../patterns/OpenTelemetry%20Trace%20Propagation%20Across%20Services.md) |
| Stateful processing | [Google Kubernetes Engine](../entities/Google%20Kubernetes%20Engine.md) | Holds open sessions in memory and scales on backlog, on Autopilot | [GKE Autopilot](../concepts/GKE%20Autopilot.md), [Decision matrix](Cloud%20Run%20vs%20GKE%20Autopilot%20Decision%20Matrix.md) |
| Deduplication ledger | [Cloud SQL for PostgreSQL](../entities/Cloud%20SQL%20for%20PostgreSQL.md) | Records each processed `event_id` under a primary key | [Idempotent consumer](../patterns/Idempotent%20Event%20Consumer%20and%20Dead-Letter%20Queue.md), [Keyless identity](../concepts/Workload%20Identity%20Federation.md) |
| Analytics | [BigQuery](../entities/BigQuery.md) | Stores events in a table partitioned by day and clustered by tenant and event type[^bq-partitioned-tables] | [Partitioning and clustering](../concepts/BigQuery%20Partitioning%20and%20Clustering.md), [Filter guardrail](../patterns/Partition%20Filter%20Enforcement%20Guardrail.md) |

## Design Decisions

- **Success means published**: The ingestion service validates, publishes, and only then answers the client. Slow or failing downstream work never holds a client connection open, and an accepted event no longer depends on the ingest instance.
- **One topic, two delivery modes**: A push subscription drives the stateless loader, and a pull subscription with ordering keys feeds the stateful consumer. [Event-Driven PubSub Pipelines](../concepts/Event-Driven%20PubSub%20Pipelines.md) explains the choice.
- **Each workload on the runtime that fits it**: Stateless, request-driven services suit Cloud Run. Stateful applications and workloads that need deep control over Kubernetes suit GKE.[^gke-and-cloud-run] [Cloud Run vs GKE Autopilot Decision Matrix](Cloud%20Run%20vs%20GKE%20Autopilot%20Decision%20Matrix.md) gives the criteria.
- **Idempotency instead of exactly-once**: Delivery is at least once, so the loader follows [Idempotent Event Consumer and Dead-Letter Queue](../patterns/Idempotent%20Event%20Consumer%20and%20Dead-Letter%20Queue.md) and the events table keeps `event_id` for read-time deduplication.
- **No stored credentials**: Cloud Run services use their attached identity, GKE pods use Workload Identity Federation for GKE, and the loader signs in to PostgreSQL with IAM database authentication. See [Workload Identity Federation](../concepts/Workload%20Identity%20Federation.md).
- **Partitioned by default**: Event tables follow [BigQuery Partitioning and Clustering](../concepts/BigQuery%20Partitioning%20and%20Clustering.md), and [Partition Filter Enforcement Guardrail](../patterns/Partition%20Filter%20Enforcement%20Guardrail.md) rejects queries that cannot prune. This replaces the layout recorded in [Legacy Unpartitioned Daily Batch Table](../concepts/Legacy%20Unpartitioned%20Daily%20Batch%20Table.md).
- **One trace per event**: The `traceparent` context travels in message attributes from the HTTP request to the warehouse write, following [OpenTelemetry Trace Propagation Across Services](../patterns/OpenTelemetry%20Trace%20Propagation%20Across%20Services.md).

## Alternative Considered

A BigQuery subscription can write messages straight to a table with no consumer code.[^pubsub-bigquery-subscriptions] The design brief set it aside because its loader also validates and reshapes payloads. It remains the simpler choice when messages can land unchanged.

## Architectural Composition

- **Stateless edge and ingestion**: Deploy bursty HTTP APIs and webhook receivers on [Cloud Run Serverless Containers](../concepts/Cloud%20Run%20Serverless%20Containers.md) so capacity follows demand, and release them with [Revision Traffic Splitting and Canary Rollback](../patterns/Revision%20Traffic%20Splitting%20and%20Canary%20Rollback.md).
- **Asynchronous backbone**: Use the delivery modes in [Event-Driven PubSub Pipelines](../concepts/Event-Driven%20PubSub%20Pipelines.md) to separate ingestion from processing and to absorb bursts.
- **Stateful and operator-driven services**: Run long-lived Kubernetes workloads, custom controllers, and multi-container pods on [GKE Autopilot](../concepts/GKE%20Autopilot.md).
- **Analytical storage layout**: Land telemetry in tables configured with [BigQuery Partitioning and Clustering](../concepts/BigQuery%20Partitioning%20and%20Clustering.md) and validate scan efficiency with [BigQuery Partition Pruning Check](../concepts/BigQuery%20Partition%20Pruning%20Check.md).

## Operating the Reference

[Production Readiness and Observability Checklist](Production%20Readiness%20and%20Observability%20Checklist.md) turns the decisions above into launch gates: keyless identity, an end-to-end trace, a tested rollback, duplicate-safe consumers, and bounded analytical scans.

## Source Context

- [Event Analytics Design Brief Summary](../sources/Event%20Analytics%20Design%20Brief%20Summary.md) supplies the components, targets, and runtime decisions.
- [BigQuery Governance Notes Summary](../sources/BigQuery%20Governance%20Notes%20Summary.md) supplies the table layout, scan, and access rules.
