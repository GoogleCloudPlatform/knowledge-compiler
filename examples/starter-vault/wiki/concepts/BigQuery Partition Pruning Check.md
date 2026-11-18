---
title: "BigQuery Partition Pruning Check"
type: Attested Computation
description: "Attested BigQuery SQL computation that ranks recent single-table queries on partitioned tables by the share of the table they scanned, exposing partition filters that fail to prune."
status: stable
tags:
  - gcp/data
  - okf/attested-computation
  - observability/query-audit
runtime: bigquery-sql
parameters:
  - name: lookback_days
    type: integer
executor:
  resource: "https://cloud.google.com/bigquery/docs/information-schema-jobs"
  receipt:
    - job_id
    - total_bytes_billed
attester:
  resource: "https://cloud.google.com/bigquery/docs/information-schema-jobs"
sources:
  - id: bq-jobs-view
    resource: "https://cloud.google.com/bigquery/docs/information-schema-jobs"
    title: "JOBS view"
  - id: bq-table-storage
    resource: "https://cloud.google.com/bigquery/docs/information-schema-table-storage"
    title: "TABLE_STORAGE view"
  - id: bq-query-partitions
    resource: "https://cloud.google.com/bigquery/docs/querying-partitioned-tables"
    title: "Query partitioned tables"
generated:
  by: "knowledge-compiler/1.2.0"
  at: "2026-11-18T00:00:00Z"
x-kc-corroborates:
  - "/wiki/concepts/BigQuery Partitioning and Clustering.md"
---

# BigQuery Partition Pruning Check

This Attested Computation turns the design rules in [BigQuery Partitioning and Clustering](BigQuery%20Partitioning%20and%20Clustering.md) into evidence. For each recent single-table query against a partitioned table, it compares the bytes the query processed with the logical size of the table it read. A `scan_ratio` near 1.0 means the query read about as much data as the table holds, so its partition filter, if it had one, pruned almost nothing.[^bq-jobs-view][^bq-table-storage]

## Parameters

| Name | Type | Meaning |
| :--- | :--- | :--- |
| `lookback_days` | integer | Trailing window of finished query jobs to audit, counted back from the time of the run. The JOBS view keeps 180 days of history. |

The weekly check in the [BigQuery Governance Notes Summary](../sources/BigQuery%20Governance%20Notes%20Summary.md) corresponds to `lookback_days = 7`; a longer window turns the same output into a trend line.[^bq-jobs-view]

## Receipt and Attestation

- **Executor**: The SQL in the Computation section runs as a BigQuery query job, and the receipt for the run is that job's `job_id` and `total_bytes_billed`.
- **Attester**: `INFORMATION_SCHEMA.JOBS` records every job in the project, including its query text, final state, and bytes billed. A consumer checks a receipt by looking up its `job_id` in the view and comparing the recorded values. A receipt that does not match is not attested.[^bq-jobs-view]
- **Permissions**: Reading every user's jobs requires `bigquery.jobs.listAll`, and reading `TABLE_STORAGE` requires table metadata access through `bigquery.tables.get` and `bigquery.tables.list`.[^bq-jobs-view][^bq-table-storage]

## Reading the Results

- **Ratio Near or Above 1.0**: The query read roughly the whole table. Check its filter on the partitioning column first: a filter whose value comes from a subquery, or that mixes in other columns, does not prune.[^bq-query-partitions]
- **Low Ratio**: Not proof of pruning. BigQuery also reads only the columns a query references, so a narrow query over every partition can still look small. Confirm with the query plan.
- **Repeat Offenders**: Group the output by `user_email` or `table_path` to find dashboards and scheduled queries that need a constant date filter, then make the filter mandatory with the [Partition Filter Enforcement Guardrail](../patterns/Partition%20Filter%20Enforcement%20Guardrail.md).
- **Out of Scope**: Unpartitioned tables such as the [Legacy Unpartitioned Daily Batch Table](Legacy%20Unpartitioned%20Daily%20Batch%20Table.md) never appear, because there is nothing to prune. Neither do queries that join several tables, since their bytes cannot be attributed to one table.

## Related Notes

- [BigQuery Partitioning and Clustering](BigQuery%20Partitioning%20and%20Clustering.md)
- [Partition Filter Enforcement Guardrail](../patterns/Partition%20Filter%20Enforcement%20Guardrail.md)
- [Legacy Unpartitioned Daily Batch Table](Legacy%20Unpartitioned%20Daily%20Batch%20Table.md)
- [BigQuery](../entities/BigQuery.md)
- [BigQuery Governance Notes Summary](../sources/BigQuery%20Governance%20Notes%20Summary.md)
- [Production Readiness and Observability Checklist](../synthesis/Production%20Readiness%20and%20Observability%20Checklist.md)
- [Google Cloud Serverless Analytics Reference](../synthesis/Google%20Cloud%20Serverless%20Analytics%20Reference.md)

# Computation

```sql
-- Rank recent single-table SELECT jobs on partitioned tables by the share of
-- each table's logical bytes they processed. Replace region-us with the
-- region that holds your datasets.
WITH recent_jobs AS (
  SELECT
    job_id,
    user_email,
    creation_time,
    total_bytes_processed,
    total_bytes_billed,
    referenced_tables[SAFE_OFFSET(0)] AS ref
  FROM `region-us`.INFORMATION_SCHEMA.JOBS
  WHERE creation_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @lookback_days DAY)
    AND job_type = 'QUERY'
    AND statement_type = 'SELECT'
    AND state = 'DONE'
    AND error_result IS NULL
    AND cache_hit IS NOT TRUE
    AND ARRAY_LENGTH(referenced_tables) = 1
),
partitioned_tables AS (
  SELECT
    project_id,
    table_schema,
    table_name,
    total_partitions,
    total_logical_bytes
  FROM `region-us`.INFORMATION_SCHEMA.TABLE_STORAGE
  WHERE deleted IS NOT TRUE
    AND total_partitions > 0
    AND total_logical_bytes > 0
)
SELECT
  j.job_id,
  j.user_email,
  j.creation_time,
  FORMAT('%s.%s.%s', t.project_id, t.table_schema, t.table_name) AS table_path,
  t.total_partitions,
  j.total_bytes_processed,
  j.total_bytes_billed,
  t.total_logical_bytes,
  ROUND(SAFE_DIVIDE(j.total_bytes_processed, t.total_logical_bytes), 3) AS scan_ratio
FROM recent_jobs AS j
JOIN partitioned_tables AS t
  ON t.project_id = j.ref.project_id
  AND t.table_schema = j.ref.dataset_id
  AND t.table_name = j.ref.table_id
ORDER BY scan_ratio DESC, j.total_bytes_billed DESC
LIMIT 50;
```
