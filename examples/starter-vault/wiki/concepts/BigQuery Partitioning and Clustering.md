---
title: "BigQuery Partitioning and Clustering"
type: concept
description: "Table layout techniques in BigQuery that divide data by a partitioning column and sort storage blocks by clustering columns, so filtered queries read less data and finish faster."
status: stable
tags:
  - gcp/data
  - architecture/analytics
  - bigquery/storage-layout
sources:
  - id: bq-partitioned-tables
    resource: "https://cloud.google.com/bigquery/docs/partitioned-tables"
    title: "Introduction to partitioned tables"
  - id: bq-query-partitions
    resource: "https://cloud.google.com/bigquery/docs/querying-partitioned-tables"
    title: "Query partitioned tables"
  - id: bq-create-partitions
    resource: "https://cloud.google.com/bigquery/docs/creating-partitioned-tables"
    title: "Create partitioned tables"
  - id: bq-clustered-tables
    resource: "https://cloud.google.com/bigquery/docs/clustered-tables"
    title: "Introduction to clustered tables"
generated:
  by: "knowledge-compiler/1.2.0"
  at: "2026-11-18T00:00:00Z"
extends:
  - "[[Cloud Run Serverless Containers]]"
corroborates:
  - "[[Partition Filter Enforcement Guardrail]]"
supersedes:
  - "[[Legacy Unpartitioned Daily Batch Table]]"
---

# BigQuery Partitioning and Clustering

Partitioning divides a [[BigQuery]] table into segments by a time-unit column, ingestion time, or an integer range. Clustering sorts the storage blocks inside each segment by the values of up to four columns. Together they let BigQuery skip data that a query cannot need, which cuts bytes processed and latency for the filtered reads that dominate analytical workloads.[^bq-partitioned-tables][^bq-clustered-tables]

This note **extends** [[Cloud Run Serverless Containers]] into the storage tier: the services and jobs described there write the events, and this layout decides how cheaply those events can be read back. It **corroborates** the [[Partition Filter Enforcement Guardrail]], because requiring a partition filter only pays off when tables are partitioned on the column that queries actually filter. It also **supersedes** the [[Legacy Unpartitioned Daily Batch Table]], the full-scan layout it replaced.

## Design Invariants

- **Partition on Event Time**: Partition append-heavy event tables on the event `TIMESTAMP` or `DATE` column, usually by day, so date-bounded queries read only the partitions in range.[^bq-partitioned-tables]
- **Filter with Constant Expressions**: Partitions are pruned only when the filter on the partitioning column is a constant expression. A filter whose value comes from table data, such as a subquery, forces a scan of every partition. Keep other columns out of the partition filter expression as well.[^bq-query-partitions]
- **Require Partition Filters**: Set `require_partition_filter = TRUE` on large tables so a query without a usable filter on the partitioning column fails instead of scanning the full history.[^bq-create-partitions]
- **Expire Old Partitions**: Set `partition_expiration_days` so partitions past their retention period are dropped automatically rather than removed with large `DELETE` statements.[^bq-create-partitions]
- **Order Clustering Columns Deliberately**: Column order sets the sort precedence. A query that filters on the first clustering column, or on the first and second together, benefits most, while a filter on only a later column benefits less.[^bq-clustered-tables]
- **Treat Estimates as Upper Bounds**: A dry run reflects partition pruning before execution, but block pruning from clustering is known only after the query runs. Measure the real effect with [[BigQuery Partition Pruning Check]].[^bq-clustered-tables]

## Reference Table Definition

This is the layout that the [[Event Analytics Design Brief Summary]] specifies for `analytics.events`: daily partitions on `event_ts`, clustering by tenant and then event type, a mandatory partition filter, and a 400-day partition expiry.

```sql
CREATE TABLE analytics.events
(
  event_id   STRING    NOT NULL,
  event_ts   TIMESTAMP NOT NULL,
  tenant_id  STRING    NOT NULL,
  event_type STRING    NOT NULL,
  session_id STRING,
  payload    JSON
)
PARTITION BY DATE(event_ts)
CLUSTER BY tenant_id, event_type
OPTIONS (
  require_partition_filter = TRUE,
  partition_expiration_days = 400
);
```

A query that filters on `event_ts >= TIMESTAMP('2026-11-01')` and `tenant_id = 'tenant-042'` reads only the partitions from November 1 onward and, within them, mostly the blocks that hold that tenant.

## Choosing Between the Two

| Need | Partitioning | Clustering |
| :--- | :--- | :--- |
| Accurate bytes estimate before the query runs | Yes, from a dry run | No, known only after execution |
| Lifecycle by date, such as expiration or overwriting one day | Yes | No |
| Filters on high-cardinality columns | Poor fit | Strong fit |
| Several filter columns at once | One partitioning column | Up to four columns |
| Small amount of data per partition, roughly under 10 GB | Avoid finer partitions | Preferred |

Large event tables often combine both: daily partitions on event time for lifecycle and pruning, and clustering on the tenant and event type keys that dashboards filter.[^bq-partitioned-tables]

## Related Notes

- [[BigQuery]]
- [[BigQuery Partition Pruning Check]]
- [[Partition Filter Enforcement Guardrail]]
- [[Legacy Unpartitioned Daily Batch Table]] (deprecated predecessor)
- [[Cloud Run Serverless Containers]]
- [[Google Cloud Serverless Analytics Reference]]
- [[BigQuery Governance Notes Summary]]
