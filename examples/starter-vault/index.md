---
okf_version: "0.3"
title: "Google Cloud Architecture Starter Vault"
description: "Clean-room OKF v0.3 sample vault compiling two illustrative raw briefs into 21 interlinked wiki notes across sources, entities, concepts, patterns, syntheses, deprecated lifecycle transitions, and an attested computation."
license: "Apache-2.0"
---

# Google Cloud Architecture Starter Vault

A clean-room **Open Knowledge Format (`OKF v0.3`)** vault demonstrating end-to-end knowledge compilation from immutable `raw/` briefs into interlinked `wiki/` notes ready for `vault-lint`, `vault-query`, and the interactive 2D/3D WebGL graph (`vault-graph`).

- **Layer 0 Anchor**: [[purpose|Starter Vault Purpose and Teleology]] (`purpose.md`)
- **Audit Log**: [[log|Audit Log]] (`log.md`)

## Raw Sources (`raw/`)

| Source Brief | Domain | Summary |
| :--- | :--- | :--- |
| [[raw/event-analytics-design-brief|Event Analytics Platform Design Brief]] | Design Brief | Illustrative design brief for a streaming event analytics platform ingesting product events through Cloud Run and Pub/Sub into partitioned BigQuery tables. |
| [[raw/bigquery-governance-notes|BigQuery Governance Notes]] | Governance Review | Illustrative governance review working notes covering BigQuery table layout rules, scan guardrails, access control, and legacy batch table retirement. |

## Source Summaries (`wiki/sources/`)

| Source Summary | Domain | Summary |
| :--- | :--- | :--- |
| [[wiki/sources/Event Analytics Design Brief Summary|Event Analytics Design Brief Summary]] | Architecture Brief | Distilled summary of the streaming event analytics brief: Cloud Run ingest, Pub/Sub delivery, idempotent loader, GKE Autopilot sessionizer, and BigQuery storage. |
| [[wiki/sources/BigQuery Governance Notes Summary|BigQuery Governance Notes Summary]] | Data Governance | Distilled summary of BigQuery governance rules (R1-R12), scan guardrails, access policies, and retirement of the legacy daily batch table. |

## Entities (`wiki/entities/`)

| Entity | Domain | Summary |
| :--- | :--- | :--- |
| [[wiki/entities/BigQuery|BigQuery]] | Data Analytics | Google Cloud's serverless data platform for SQL analytics with partitioned and clustered tables, streaming ingestion, and queryable job metadata. |
| [[wiki/entities/Cloud PubSub|Cloud PubSub]] | Messaging | Asynchronous messaging service that decouples event producers from consumers through topics and push, pull, or export subscriptions. |
| [[wiki/entities/Cloud Run|Cloud Run]] | Serverless Compute | Managed platform for running containers as request-driven services and run-to-completion jobs without managing servers or clusters. |
| [[wiki/entities/Cloud SQL for PostgreSQL|Cloud SQL for PostgreSQL]] | Relational Database | Managed PostgreSQL service used as the transactional deduplication ledger behind an idempotent event consumer. |
| [[wiki/entities/Google Kubernetes Engine|Google Kubernetes Engine]] | Managed Kubernetes | Managed Kubernetes service, offered in Autopilot and Standard modes, for workloads that need the full Kubernetes API. |

## Core Concepts (`wiki/concepts/`)

| Concept | Domain | Summary |
| :--- | :--- | :--- |
| [[wiki/concepts/BigQuery Partitioning and Clustering|BigQuery Partitioning and Clustering]] | Analytics | Table layout techniques that divide data by a partitioning column and sort storage blocks by clustering columns to reduce scanned bytes and latency. |
| [[wiki/concepts/BigQuery Partition Pruning Check|BigQuery Partition Pruning Check]] | Attested Computation | OKF v0.3 SQL computation joining `INFORMATION_SCHEMA.JOBS` with `TABLE_STORAGE` to surface queries whose partition filters fail to prune. |
| [[wiki/concepts/Cloud Run Serverless Containers|Cloud Run Serverless Containers]] | Compute | Request-driven container runtime for stateless services and run-to-completion jobs, scaling from zero without cluster operations. |
| [[wiki/concepts/Event-Driven PubSub Pipelines|Event-Driven PubSub Pipelines]] | Messaging | Design principles for decoupling producers and consumers with Pub/Sub topics, push/pull delivery, ordering keys, dead-lettering, and backpressure. |
| [[wiki/concepts/GKE Autopilot|GKE Autopilot]] | Kubernetes | GKE mode where Google Cloud provisions, scales, upgrades, and hardens nodes per pod request so teams operate workloads rather than VMs. |
| [[wiki/concepts/Legacy Unpartitioned Daily Batch Table|Legacy Unpartitioned Daily Batch Table]] | Analytics (Deprecated) | Deprecated layout (`status: deprecated`, `superseded_by` partitioned layout) where nightly batch appends force full-table scans. |
| [[wiki/concepts/Workload Identity Federation|Workload Identity Federation]] | Security | Keyless authentication exchanging platform-issued OIDC, SAML, or Kubernetes credentials for short-lived Google Cloud tokens instead of JSON keys. |

## Architectural Patterns (`wiki/patterns/`)

| Pattern | Domain | Summary |
| :--- | :--- | :--- |
| [[wiki/patterns/Idempotent Event Consumer and Dead-Letter Queue|Idempotent Event Consumer and Dead-Letter Queue]] | Reliability | Pairs a transactional deduplication ledger with a dead-letter topic so at-least-once Pub/Sub delivery produces one durable effect. |
| [[wiki/patterns/OpenTelemetry Trace Propagation Across Services|OpenTelemetry Trace Propagation Across Services]] | Observability | Propagates one W3C `traceparent` context from HTTP ingest through Cloud Run and Pub/Sub into Cloud SQL for end-to-end Cloud Trace visibility. |
| [[wiki/patterns/Partition Filter Enforcement Guardrail|Partition Filter Enforcement Guardrail]] | Governance | Enforces `require_partition_filter` on large partitioned BigQuery tables so unpruned full-table scan queries fail before execution. |
| [[wiki/patterns/Revision Traffic Splitting and Canary Rollback|Revision Traffic Splitting and Canary Rollback]] | Delivery | Deploys new Cloud Run revisions at zero traffic, shifts requests in stepped holds, and routes traffic back to the last good revision when health signals leave the SLO. |

## Synthesis (`wiki/synthesis/`)

| Synthesis | Domain | Summary |
| :--- | :--- | :--- |
| [[wiki/synthesis/Google Cloud Serverless Analytics Reference|Google Cloud Serverless Analytics Reference]] | Reference Architecture | End-to-end streaming analytics blueprint connecting Cloud Run, Pub/Sub, GKE Autopilot, Cloud SQL for PostgreSQL, and partitioned BigQuery. |
| [[wiki/synthesis/Cloud Run vs GKE Autopilot Decision Matrix|Cloud Run vs GKE Autopilot Decision Matrix]] | Decision Matrix | Criteria and illustrative workload mix for placing containerized services on Cloud Run versus GKE Autopilot. |
| [[wiki/synthesis/Production Readiness and Observability Checklist|Production Readiness and Observability Checklist]] | Operations | Five ordered launch gates covering keyless identity, end-to-end tracing, canary rollouts, duplicate-safe consumers, and bounded scans. |
