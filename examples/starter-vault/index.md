---
okf_version: "0.3"
title: "Google Cloud Architecture Starter Vault"
description: "Clean-room OKF v0.3 sample vault compiling two illustrative raw briefs into 21 interlinked wiki notes across sources, entities, concepts, patterns, syntheses, deprecated lifecycle transitions, and an attested computation."
license: "Apache-2.0"
---

# Google Cloud Architecture Starter Vault

A clean-room **Open Knowledge Format (`OKF v0.3`)** vault demonstrating end-to-end knowledge compilation from immutable `raw/` briefs into interlinked `wiki/` notes ready for `vault-lint`, `vault-query`, and the interactive 2D/3D WebGL graph (`vault-graph`).

- **Layer 0 Anchor**: [Starter Vault Purpose and Teleology](purpose.md) (`purpose.md`)
- **Wiki Directory**: [Wiki Index](wiki/index.md) (`wiki/index.md`, OKF v0.3 §8 progressive-disclosure subdirectory indexes)
- **Audit Log**: [Audit Log](log.md) (`log.md`)

## Raw Sources (`raw/`)

| Source Brief | Domain | Summary |
| :--- | :--- | :--- |
| [Event Analytics Platform Design Brief](raw/event-analytics-design-brief.md) | Design Brief | Illustrative design brief for a streaming event analytics platform ingesting product events through Cloud Run and Pub/Sub into partitioned BigQuery tables. |
| [BigQuery Governance Notes](raw/bigquery-governance-notes.md) | Governance Review | Illustrative governance review working notes covering BigQuery table layout rules, scan guardrails, access control, and legacy batch table retirement. |

## Source Summaries (`wiki/sources/`)

| Source Summary | Domain | Summary |
| :--- | :--- | :--- |
| [Event Analytics Design Brief Summary](wiki/sources/Event%20Analytics%20Design%20Brief%20Summary.md) | Architecture Brief | Distilled summary of the streaming event analytics brief: Cloud Run ingest, Pub/Sub delivery, idempotent loader, GKE Autopilot sessionizer, and BigQuery storage. |
| [BigQuery Governance Notes Summary](wiki/sources/BigQuery%20Governance%20Notes%20Summary.md) | Data Governance | Distilled summary of BigQuery governance rules (R1-R12), scan guardrails, access policies, and retirement of the legacy daily batch table. |

## Entities (`wiki/entities/`)

| Entity | Domain | Summary |
| :--- | :--- | :--- |
| [BigQuery](wiki/entities/BigQuery.md) | Data Analytics | Google Cloud's serverless data platform for SQL analytics with partitioned and clustered tables, streaming ingestion, and queryable job metadata. |
| [Cloud PubSub](wiki/entities/Cloud%20PubSub.md) | Messaging | Asynchronous messaging service that decouples event producers from consumers through topics and push, pull, or export subscriptions. |
| [Cloud Run](wiki/entities/Cloud%20Run.md) | Serverless Compute | Managed platform for running containers as request-driven services and run-to-completion jobs without managing servers or clusters. |
| [Cloud SQL for PostgreSQL](wiki/entities/Cloud%20SQL%20for%20PostgreSQL.md) | Relational Database | Managed PostgreSQL service used as the transactional deduplication ledger behind an idempotent event consumer. |
| [Google Kubernetes Engine](wiki/entities/Google%20Kubernetes%20Engine.md) | Managed Kubernetes | Managed Kubernetes service, offered in Autopilot and Standard modes, for workloads that need the full Kubernetes API. |

## Core Concepts (`wiki/concepts/`)

| Concept | Domain | Summary |
| :--- | :--- | :--- |
| [BigQuery Partitioning and Clustering](wiki/concepts/BigQuery%20Partitioning%20and%20Clustering.md) | Analytics | Table layout techniques that divide data by a partitioning column and sort storage blocks by clustering columns to reduce scanned bytes and latency. |
| [BigQuery Partition Pruning Check](wiki/concepts/BigQuery%20Partition%20Pruning%20Check.md) | Attested Computation | OKF v0.3 SQL computation joining `INFORMATION_SCHEMA.JOBS` with `TABLE_STORAGE` to surface queries whose partition filters fail to prune. |
| [Cloud Run Serverless Containers](wiki/concepts/Cloud%20Run%20Serverless%20Containers.md) | Compute | Request-driven container runtime for stateless services and run-to-completion jobs, scaling from zero without cluster operations. |
| [Event-Driven PubSub Pipelines](wiki/concepts/Event-Driven%20PubSub%20Pipelines.md) | Messaging | Design principles for decoupling producers and consumers with Pub/Sub topics, push/pull delivery, ordering keys, dead-lettering, and backpressure. |
| [GKE Autopilot](wiki/concepts/GKE%20Autopilot.md) | Kubernetes | GKE mode where Google Cloud provisions, scales, upgrades, and hardens nodes per pod request so teams operate workloads rather than VMs. |
| [Legacy Unpartitioned Daily Batch Table](wiki/concepts/Legacy%20Unpartitioned%20Daily%20Batch%20Table.md) | Analytics (Deprecated) | Deprecated layout (`status: deprecated`, `superseded_by` partitioned layout) where nightly batch appends force full-table scans. |
| [Workload Identity Federation](wiki/concepts/Workload%20Identity%20Federation.md) | Security | Keyless authentication exchanging platform-issued OIDC, SAML, or Kubernetes credentials for short-lived Google Cloud tokens instead of JSON keys. |

## Architectural Patterns (`wiki/patterns/`)

| Pattern | Domain | Summary |
| :--- | :--- | :--- |
| [Idempotent Event Consumer and Dead-Letter Queue](wiki/patterns/Idempotent%20Event%20Consumer%20and%20Dead-Letter%20Queue.md) | Reliability | Pairs a transactional deduplication ledger with a dead-letter topic so at-least-once Pub/Sub delivery produces one durable effect. |
| [OpenTelemetry Trace Propagation Across Services](wiki/patterns/OpenTelemetry%20Trace%20Propagation%20Across%20Services.md) | Observability | Propagates one W3C `traceparent` context from HTTP ingest through Cloud Run and Pub/Sub into Cloud SQL for end-to-end Cloud Trace visibility. |
| [Partition Filter Enforcement Guardrail](wiki/patterns/Partition%20Filter%20Enforcement%20Guardrail.md) | Governance | Enforces `require_partition_filter` on large partitioned BigQuery tables so unpruned full-table scan queries fail before execution. |
| [Revision Traffic Splitting and Canary Rollback](wiki/patterns/Revision%20Traffic%20Splitting%20and%20Canary%20Rollback.md) | Delivery | Deploys new Cloud Run revisions at zero traffic, shifts requests in stepped holds, and routes traffic back to the last good revision when health signals leave the SLO. |

## Synthesis (`wiki/synthesis/`)

| Synthesis | Domain | Summary |
| :--- | :--- | :--- |
| [Google Cloud Serverless Analytics Reference](wiki/synthesis/Google%20Cloud%20Serverless%20Analytics%20Reference.md) | Reference Architecture | End-to-end streaming analytics blueprint connecting Cloud Run, Pub/Sub, GKE Autopilot, Cloud SQL for PostgreSQL, and partitioned BigQuery. |
| [Cloud Run vs GKE Autopilot Decision Matrix](wiki/synthesis/Cloud%20Run%20vs%20GKE%20Autopilot%20Decision%20Matrix.md) | Decision Matrix | Criteria and illustrative workload mix for placing containerized services on Cloud Run versus GKE Autopilot. |
| [Production Readiness and Observability Checklist](wiki/synthesis/Production%20Readiness%20and%20Observability%20Checklist.md) | Operations | Five ordered launch gates covering keyless identity, end-to-end tracing, canary rollouts, duplicate-safe consumers, and bounded scans. |
