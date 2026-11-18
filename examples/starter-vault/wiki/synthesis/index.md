# Synthesis

OKF v0.3 subdirectory index for `wiki/synthesis/` (see [Master Index](../../index.md) and [Wiki Index](../index.md)).

- [Cloud Run vs GKE Autopilot Decision Matrix](Cloud%20Run%20vs%20GKE%20Autopilot%20Decision%20Matrix.md): Criteria for placing a containerized workload on Cloud Run or GKE Autopilot, with a decision table and an illustrative workload mix.
- [Google Cloud Serverless Analytics Reference](Google%20Cloud%20Serverless%20Analytics%20Reference.md): Reference architecture combining Cloud Run ingestion and loading, Pub/Sub delivery, a stateful GKE Autopilot consumer, a Cloud SQL for PostgreSQL deduplication ledger, and partitioned BigQuery analytics.
- [Production Readiness and Observability Checklist](Production%20Readiness%20and%20Observability%20Checklist.md): Five launch gates for the serverless analytics reference: keyless identity, end-to-end tracing, safe rollout, duplicate-safe consumers, and bounded analytical scans.
