---
title: "BigQuery Governance Notes"
type: raw-source
description: "Illustrative working notes from a data platform governance review covering table layout rules, scan guardrails, access control, and the retirement of a legacy unpartitioned batch table."
status: stable
tags:
  - raw/working-notes
  - gcp/bigquery
  - governance/data
sources:
  - id: bq-partitioned-tables
    resource: "https://cloud.google.com/bigquery/docs/partitioned-tables"
    title: "Introduction to partitioned tables"
  - id: bq-clustered-tables
    resource: "https://cloud.google.com/bigquery/docs/clustered-tables"
    title: "Introduction to clustered tables"
  - id: bq-query-partitioned
    resource: "https://cloud.google.com/bigquery/docs/querying-partitioned-tables"
    title: "Query partitioned tables"
  - id: bq-manage-partitioned
    resource: "https://cloud.google.com/bigquery/docs/managing-partitioned-tables"
    title: "Manage partitioned tables"
  - id: bq-custom-quotas
    resource: "https://cloud.google.com/bigquery/docs/custom-quotas"
    title: "Create custom query quotas"
  - id: bq-jobs-view
    resource: "https://cloud.google.com/bigquery/docs/information-schema-jobs"
    title: "JOBS view"
  - id: bq-column-security
    resource: "https://cloud.google.com/bigquery/docs/column-level-security-intro"
    title: "Introduction to column-level access control"
  - id: bq-row-security
    resource: "https://cloud.google.com/bigquery/docs/row-level-security-intro"
    title: "Introduction to BigQuery row-level security"
generated:
  by: "knowledge-compiler/1.2.0"
  at: "2026-11-18T00:00:00Z"
---

# BigQuery Governance Notes

> Illustrative sample source for the starter vault. The dataset names, table names, team names, and thresholds are fictional.

| Field | Value |
| :--- | :--- |
| Document type | Working notes from a governance review |
| Authoring team | Data platform team |
| Review state | Agreed, pending rollout |
| Scope | Datasets `analytics`, `staging`, and `sandbox` in the analytics project |

## 1. Why This Review Happened

Two symptoms triggered the review. Dashboard queries against the event history had become slow and read far more data than their date filters implied. And nobody could say with confidence who was allowed to read user-level columns. Both trace back to the same table.

## 2. Finding: The Legacy Daily Batch Table

`analytics.events_daily_batch` is an unpartitioned table that a batch load appends to once a night. It has grown for three years. Because it has neither partitions nor clustering, a query that asks for yesterday reads the same bytes as a query that asks for everything.

**Decision:** the table is deprecated. `analytics.events`, partitioned by day and fed by the streaming pipeline, replaces it.

Retirement steps:

1. Backfill history into `analytics.events` with an `INSERT ... SELECT` from the legacy table.
2. Repoint dashboards to a compatibility view, `analytics.events_daily_batch_v`, that selects from the new table. Readers move without rewriting every query, but each query now has to carry a date filter.
3. Run both tables side by side for 30 days and compare daily row counts.
4. Stop the nightly load, then delete the legacy table.

## 3. Table Layout Rules

- **R1.** Any table in `analytics` that holds events or facts is partitioned on the date or timestamp column that queries filter by most often. Daily granularity is the default. Hourly granularity is allowed only when queries routinely target a few hours of data.[^bq-partitioned-tables]
- **R2.** Tables are clustered on up to four columns, ordered from the most frequently filtered to the least. For event tables that is `tenant_id`, then `event_type`.[^bq-clustered-tables]
- **R3.** Every partitioned table in `analytics` sets `require_partition_filter`. A query that omits a filter on the partitioning column fails with an error and does not scan the table.[^bq-query-partitioned]
- **R4.** Raw event partitions expire after 400 days.[^bq-manage-partitioned] Tables in `sandbox` expire after 7 days through the dataset's default table expiration.

## 4. Scan Guardrails

- **R5.** Scheduled queries and dashboard connections set a maximum bytes billed value. A query that would read more than the limit fails and does not run.
- **R6.** The project sets a daily query usage quota at project level and a second one per user.[^bq-custom-quotas]
- **R7.** A pruning check runs weekly. It reads `INFORMATION_SCHEMA.JOBS` for the last 7 days, finds the queries that referenced `analytics.events`, and lists the jobs with the highest bytes processed together with the submitting user. The view keeps job history for 180 days, so the same check can also produce a trend line.[^bq-jobs-view]

## 5. Access Control

- **R8.** Access is granted to groups at dataset level, never to individuals at table level. Analysts get read access to `analytics`. Only pipeline service accounts can write.
- **R9.** Columns that identify a person (`user_id`, `ip_address`, `email`) carry policy tags. Only members of the privacy-reviewed group can read them. Everyone else can still query the remaining columns.[^bq-column-security]
- **R10.** Tenant-facing reports read through row-level access policies that filter on `tenant_id`.[^bq-row-security]
- **R11.** Pipelines authenticate with the service identity attached to their runtime. Service account keys are not issued for warehouse access.

## 6. Attribution

- **R12.** Datasets and query jobs carry `team`, `env`, and `data_domain` labels, so usage in the job history can be grouped by owner.

## 7. Open Items

1. Should the pruning check fail a deployment when a new scheduled query scans more than an agreed number of partitions, or should it only report?
2. Does `sandbox` need the partition filter rule, given its 7-day expiry?
3. Who owns the policy tag taxonomy once the privacy review group is formed?
