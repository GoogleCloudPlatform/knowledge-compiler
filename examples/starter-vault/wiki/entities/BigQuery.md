---
title: "BigQuery"
type: entity
description: "Google Cloud's fully managed, serverless data platform for SQL analytics, with partitioned and clustered tables, streaming ingestion, and queryable job metadata."
status: stable
tags:
  - gcp/analytics
  - gcp/bigquery
  - entity/product
sources:
  - id: bq-overview
    resource: "https://cloud.google.com/bigquery/docs/introduction"
    title: "BigQuery overview"
  - id: bq-partitioned-tables
    resource: "https://cloud.google.com/bigquery/docs/partitioned-tables"
    title: "Introduction to partitioned tables"
  - id: bq-clustered-tables
    resource: "https://cloud.google.com/bigquery/docs/clustered-tables"
    title: "Introduction to clustered tables"
  - id: bq-write-api
    resource: "https://cloud.google.com/bigquery/docs/write-api-grpc"
    title: "Introduction to the Storage Write API (gRPC)"
  - id: bq-jobs-view
    resource: "https://cloud.google.com/bigquery/docs/information-schema-jobs"
    title: "JOBS view"
  - id: bq-access-control
    resource: "https://cloud.google.com/bigquery/docs/access-control"
    title: "BigQuery IAM roles and permissions"
  - id: design-brief
    resource: "/raw/event-analytics-design-brief.md"
    title: "Event Analytics Platform Design Brief"
    author: "team:cloud-platform"
  - id: governance-notes
    resource: "/raw/bigquery-governance-notes.md"
    title: "BigQuery Governance Notes"
    author: "team:data-platform"
generated:
  by: "knowledge-compiler/1.2.0"
  at: "2026-11-18T00:00:00Z"
complements:
  - "[[BigQuery Partitioning and Clustering]]"
  - "[[Partition Filter Enforcement Guardrail]]"
  - "[[BigQuery Partition Pruning Check]]"
---

# BigQuery

**BigQuery** is Google Cloud's fully managed data platform for analytics. Its serverless architecture lets you query data with SQL without managing infrastructure, and its compute and storage layers are separate, so each can allocate resources without affecting the other.[^bq-overview]

## Key Capabilities

- **Partitioned tables**: A table can be divided into partitions by a time-unit column, by ingestion time, or by an integer range. When a query filters on the partitioning column, BigQuery scans the matching partitions and skips the rest, a process called pruning.[^bq-partitioned-tables]
- **Clustered tables**: Data is sorted in storage blocks by up to four clustering columns, so queries that filter or aggregate on those columns scan only the relevant blocks. The order of the columns matters.[^bq-clustered-tables]
- **Streaming ingestion**: The Storage Write API appends rows over a streaming connection. Its default stream gives at-least-once semantics, and application-created streams add exactly-once writes through stream offsets.[^bq-write-api]
- **Job metadata as data**: The `INFORMATION_SCHEMA.JOBS` view returns one row per job, including the submitting user and the bytes processed, and keeps 180 days of history.[^bq-jobs-view]
- **Access control with IAM**: Roles can be granted on projects, datasets, tables, and views.[^bq-access-control]

## Role in the Reference Architecture

BigQuery is the analytical store in the design brief and the subject of the governance notes. The settings below come from those two sources.[^design-brief][^governance-notes]

| Decision | Setting | Stated in |
| :--- | :--- | :--- |
| Partitioning | Daily, on `event_ts` | [[Event Analytics Design Brief Summary|Design brief]] |
| Clustering | `tenant_id`, then `event_type` | [[Event Analytics Design Brief Summary|Design brief]] |
| Ingestion | Storage Write API appends from the loader | [[Event Analytics Design Brief Summary|Design brief]] |
| Partition filter | Required on every partitioned table in the `analytics` dataset | [[BigQuery Governance Notes Summary|Governance notes]] |
| Retention | Raw event partitions expire after 400 days | [[BigQuery Governance Notes Summary|Governance notes]] |
| Verification | Weekly pruning check over the last 7 days of jobs | [[BigQuery Governance Notes Summary|Governance notes]] |

Three notes build on this table layout. [[BigQuery Partitioning and Clustering]] explains it, [[Partition Filter Enforcement Guardrail]] enforces it, and [[BigQuery Partition Pruning Check]] measures whether queries benefit from it. The table it replaces is described in [[Legacy Unpartitioned Daily Batch Table]].

## Operating Notes

- **Expect duplicates upstream**: Delivery into the events table is at-least-once. Consumers that need exact counts read through a view that keeps one row per `event_id`.[^design-brief] See [[Idempotent Event Consumer and Dead-Letter Queue]].
- **Grant to groups, write as services**: Analysts read through group grants at dataset level, and only pipeline service accounts can write.[^governance-notes]
- **Protect personal columns**: The governance notes put policy tags on user-level columns and row-level policies on tenant-facing reports.[^governance-notes]
- **Label for attribution**: Datasets and query jobs carry `team`, `env`, and `data_domain` labels, so the job history can be grouped by owner.[^governance-notes]
- **Know the upstream path**: Events reach BigQuery from [[Cloud PubSub|Pub/Sub]] through a loader on [[Cloud Run]]. See [[Event-Driven PubSub Pipelines]].

## Related Notes

- Concepts: [[BigQuery Partitioning and Clustering]], [[BigQuery Partition Pruning Check]], [[Legacy Unpartitioned Daily Batch Table]]
- Pattern: [[Partition Filter Enforcement Guardrail]]
- Sources: [[BigQuery Governance Notes Summary]], [[Event Analytics Design Brief Summary]]
- Synthesis: [[Google Cloud Serverless Analytics Reference]], [[Production Readiness and Observability Checklist]]
