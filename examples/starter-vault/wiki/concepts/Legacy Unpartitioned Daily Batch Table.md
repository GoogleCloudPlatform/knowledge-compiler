---
title: "Legacy Unpartitioned Daily Batch Table"
type: concept
description: "Deprecated BigQuery layout in which a nightly batch job appends each day's export to one unpartitioned table, forcing full-table scans; superseded by partitioned and clustered tables."
status: deprecated
superseded_by: "/wiki/concepts/BigQuery Partitioning and Clustering.md"
tags:
  - gcp/data
  - lifecycle/deprecated
  - anti-pattern/full-table-scan
sources:
  - id: bq-partitioned-tables
    resource: "https://cloud.google.com/bigquery/docs/partitioned-tables"
    title: "Introduction to partitioned tables"
  - id: bq-create-partitions
    resource: "https://cloud.google.com/bigquery/docs/creating-partitioned-tables"
    title: "Create partitioned tables"
  - id: bq-load-partitions
    resource: "https://cloud.google.com/bigquery/docs/load-data-partitioned-tables"
    title: "Load data into partitioned tables"
generated:
  by: "knowledge-compiler/1.2.0"
  at: "2026-11-18T00:00:00Z"
---

# Legacy Unpartitioned Daily Batch Table

> [!WARNING] Deprecated
> This layout is superseded by [[BigQuery Partitioning and Clustering]]. The note stays in the vault so that older runbooks and queries that mention it still resolve, and so that the migration path below is easy to find.

In this layout, a nightly batch job loads the previous day's export into a single unpartitioned [[BigQuery]] table, appending each day's rows and occasionally reloading the whole table. A common variant writes one table per day, such as `events_20261117`, and queries them with wildcard tables. Both work while data is small. Neither scales.

The [[BigQuery Governance Notes Summary]] records a concrete case: `analytics.events_daily_batch`, three years of nightly appends that every query read in full, retired in favor of the day-partitioned `analytics.events` table fed by streaming.

## Why It Was Retired

- **Every Query Scans Everything**: Without a partitioning column there is nothing to prune, so a query for yesterday's events reads the full history and bytes processed grow with every nightly load.[^bq-partitioned-tables]
- **No Partition Filter Enforcement**: `require_partition_filter` applies only to partitioned tables, so nothing stops a dashboard from running full scans. The [[Partition Filter Enforcement Guardrail]] treats this layout as a violation.[^bq-create-partitions]
- **Retention Means Rewrites**: Removing old data takes `DELETE` statements over the whole table instead of letting partitions expire on their own.
- **Reloads Are Not Idempotent**: Rerunning a failed night appends the same rows a second time unless the job deletes them first, because there is no single partition to overwrite.
- **Date-Sharded Variant**: Per-day tables make BigQuery keep a separate schema and metadata for each shard, and may require a permission check on every table a query touches, which adds query overhead. Partitioned tables perform better.[^bq-partitioned-tables]

## Migration Path

1. **Backfill the Replacement**: Copy history into a partitioned and clustered table with `INSERT ... SELECT` from the legacy table, or create one with `CREATE TABLE ... PARTITION BY ... CLUSTER BY ... AS SELECT`, following [[BigQuery Partitioning and Clustering]]. Set `require_partition_filter` and a partition expiration from day one.[^bq-create-partitions]
2. **Convert Shards**: For the date-sharded variant, the `bq partition` command converts a set of shards into a single ingestion-time partitioned table.[^bq-create-partitions]
3. **Keep Readers Working**: Repoint dashboards to a compatibility view, such as `analytics.events_daily_batch_v`, that selects from the new table. Queries through the view must now carry a date filter.
4. **Run Side by Side**: Keep both tables for a validation window, compare daily row counts, and confirm pruning with [[BigQuery Partition Pruning Check]].
5. **Retire the Batch Load**: Stop the nightly load, then delete the legacy table. If a batch feed has to stay, point it at the day's partition with a partition decorator and load with `--replace=true`, so a rerun overwrites that one day instead of duplicating it.[^bq-load-partitions]

## Related Notes

- [[BigQuery Partitioning and Clustering]] (replacement)
- [[Partition Filter Enforcement Guardrail]]
- [[BigQuery Partition Pruning Check]]
- [[BigQuery]]
- [[BigQuery Governance Notes Summary]]
