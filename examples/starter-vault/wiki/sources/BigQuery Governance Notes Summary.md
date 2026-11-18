---
title: "BigQuery Governance Notes Summary"
type: source-summary
description: "Summary of data platform governance notes for BigQuery: partitioning and clustering rules, scan guardrails, access control, and the retirement of a legacy unpartitioned batch table."
status: stable
tags:
  - source/working-notes
  - gcp/bigquery
  - governance/data
sources:
  - id: governance-notes
    resource: "/raw/bigquery-governance-notes.md"
    title: "BigQuery Governance Notes"
    author: "team:data-platform"
generated:
  by: "knowledge-compiler/1.2.0"
  at: "2026-11-18T00:00:00Z"
x-kc-corroborates:
  - "/wiki/concepts/BigQuery Partitioning and Clustering.md"
  - "/wiki/patterns/Partition Filter Enforcement Guardrail.md"
x-kc-extends:
  - "/wiki/sources/Event Analytics Design Brief Summary.md"
---

# BigQuery Governance Notes Summary

Distilled from [BigQuery Governance Notes](../../raw/bigquery-governance-notes.md), working notes from a data platform governance review.[^governance-notes]

## Thesis

Slow dashboards and unclear access to user-level columns had one root cause: a three-year-old unpartitioned table that every query read in full. The notes deprecate that table and set twelve rules so that its replacement stays efficient to query and simple to audit.[^governance-notes]

## Key Takeaways

- **Deprecate, do not patch**: The nightly-appended table is retired in favor of a day-partitioned table fed by streaming. See [Legacy Unpartitioned Daily Batch Table](../concepts/Legacy%20Unpartitioned%20Daily%20Batch%20Table.md) for the old design and [BigQuery Partitioning and Clustering](../concepts/BigQuery%20Partitioning%20and%20Clustering.md) for the layout that replaces it.
- **Make the efficient query the only query**: Partitioned tables require a partition filter, so a query without one fails and scans nothing. See [Partition Filter Enforcement Guardrail](../patterns/Partition%20Filter%20Enforcement%20Guardrail.md).
- **Verify, do not assume**: A weekly check over job metadata lists the heaviest queries against the events table. See [BigQuery Partition Pruning Check](../concepts/BigQuery%20Partition%20Pruning%20Check.md).
- **Groups and tags, not individuals**: Access is granted to groups at dataset level, personal columns carry policy tags, and tenant-facing reports read through row-level policies.
- **Keyless pipelines**: Writers authenticate with the identity attached to their runtime. See [Workload Identity Federation](../concepts/Workload%20Identity%20Federation.md).

## Rules by Theme

| Theme | Rules | What they require |
| :--- | :--- | :--- |
| Table layout | R1 to R4 | Partition on the most-filtered date column (daily by default), cluster on up to four columns in filter order, require a partition filter, expire raw event partitions after 400 days |
| Scan guardrails | R5 to R7 | A maximum bytes billed value on scheduled and dashboard queries, daily query quotas per project and per user, a weekly pruning check over the last 7 days of jobs |
| Access control | R8 to R11 | Group grants at dataset level, policy tags on `user_id`, `ip_address`, and `email`, row-level policies on `tenant_id`, no service account keys |
| Attribution | R12 | `team`, `env`, and `data_domain` labels on datasets and query jobs |

## Retirement Plan for the Legacy Table

1. Backfill history into the partitioned table.
2. Repoint dashboards to a compatibility view over the new table. Every query now has to carry a date filter.
3. Run both tables side by side for 30 days and compare daily row counts.
4. Stop the nightly load, then delete the legacy table.

## Relationship to the Design Brief

The [Event Analytics Design Brief Summary](Event%20Analytics%20Design%20Brief%20Summary.md) specifies the partitioned events table from the pipeline side: day partitions on `event_ts`, clustering by tenant and event type, and a 400-day expiry. These notes extend that specification with the rules that govern the table once it exists: who can read which columns, how scans are capped, and how pruning is verified.[^governance-notes] The two sources agree on every setting they both mention.

## Open Items

- Should the pruning check block a deployment, or only report?
- Does the short-lived `sandbox` dataset need the partition filter rule?
- Who owns the policy tag taxonomy?

## Where This Source Is Used

- Entity: [BigQuery](../entities/BigQuery.md)
- Concepts: [BigQuery Partitioning and Clustering](../concepts/BigQuery%20Partitioning%20and%20Clustering.md), [Legacy Unpartitioned Daily Batch Table](../concepts/Legacy%20Unpartitioned%20Daily%20Batch%20Table.md), [BigQuery Partition Pruning Check](../concepts/BigQuery%20Partition%20Pruning%20Check.md)
- Pattern: [Partition Filter Enforcement Guardrail](../patterns/Partition%20Filter%20Enforcement%20Guardrail.md)
- Synthesis: [Google Cloud Serverless Analytics Reference](../synthesis/Google%20Cloud%20Serverless%20Analytics%20Reference.md), [Production Readiness and Observability Checklist](../synthesis/Production%20Readiness%20and%20Observability%20Checklist.md)
