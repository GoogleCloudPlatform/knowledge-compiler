---
title: "Cloud SQL for PostgreSQL"
type: entity
description: "Google Cloud's fully managed PostgreSQL service, used in this vault as the transactional store behind an idempotent event consumer."
status: stable
tags:
  - gcp/databases
  - gcp/postgresql
  - entity/product
sources:
  - id: sql-overview
    resource: "https://cloud.google.com/sql/docs/postgres/introduction"
    title: "Cloud SQL overview"
  - id: sql-ha
    resource: "https://cloud.google.com/sql/docs/postgres/high-availability"
    title: "About high availability"
  - id: sql-iam-auth
    resource: "https://cloud.google.com/sql/docs/postgres/iam-authentication"
    title: "IAM authentication"
  - id: sql-auth-proxy
    resource: "https://cloud.google.com/sql/docs/postgres/sql-proxy"
    title: "About the Cloud SQL Auth Proxy"
  - id: sql-connect-run
    resource: "https://cloud.google.com/sql/docs/postgres/connect-run"
    title: "Connect from Cloud Run"
  - id: sql-connect-gke
    resource: "https://cloud.google.com/sql/docs/postgres/connect-kubernetes-engine"
    title: "Connect from Google Kubernetes Engine"
  - id: sql-connections
    resource: "https://cloud.google.com/sql/docs/postgres/manage-connections"
    title: "Manage database connections"
  - id: design-brief
    resource: "/raw/event-analytics-design-brief.md"
    title: "Event Analytics Platform Design Brief"
    author: "team:cloud-platform"
generated:
  by: "knowledge-compiler/1.2.0"
  at: "2026-11-18T00:00:00Z"
x-kc-complements:
  - "/wiki/patterns/Idempotent Event Consumer and Dead-Letter Queue.md"
  - "/wiki/concepts/Workload Identity Federation.md"
  - "/wiki/entities/Cloud Run.md"
---

# Cloud SQL for PostgreSQL

**Cloud SQL for PostgreSQL** is Cloud SQL, Google Cloud's fully managed relational database service, running the PostgreSQL database engine. The service takes over database administration tasks, and applications connect with standard PostgreSQL clients.[^sql-overview]

## Key Capabilities

- **High availability**: An instance configured for high availability is a regional instance with a primary and a standby in two zones. Every write is replicated synchronously to disks in both zones before the transaction is reported as committed.[^sql-ha]
- **IAM database authentication**: A user or service account can sign in with an IAM access token in place of a database password.[^sql-iam-auth]
- **Authorized, encrypted connections**: The Cloud SQL Auth Proxy uses IAM permissions to decide who can connect and encrypts the connection, with no need for authorized networks or manual SSL configuration.[^sql-auth-proxy]
- **Documented paths from both runtimes**: Cloud Run and GKE each have a supported way to connect.[^sql-connect-run][^sql-connect-gke]

## Role in the Reference Architecture

In the design brief, Cloud SQL for PostgreSQL holds the `processed_events` ledger that makes the loader idempotent. The ledger has a primary key on `event_id`.[^design-brief]

| Step | Loader action | Effect |
| :--- | :--- | :--- |
| 1 | Look up the message's `event_id` in the ledger | If present, acknowledge and stop |
| 2 | Append the row to [BigQuery](BigQuery.md) | The event becomes queryable |
| 3 | Insert the `event_id` into the ledger | Later redeliveries are recognized |
| 4 | Return success to [Pub/Sub](Cloud%20PubSub.md) | The message is acknowledged |

A crash between steps 2 and 3 can leave a duplicate row. The brief accepts that window and handles it with a deduplicating view. [Idempotent Event Consumer and Dead-Letter Queue](../patterns/Idempotent%20Event%20Consumer%20and%20Dead-Letter%20Queue.md) describes the general pattern.

The loader signs in with IAM database authentication, so the path from [Cloud Run](Cloud%20Run.md) to the database holds no stored password and no key file.[^design-brief] See [Workload Identity Federation](../concepts/Workload%20Identity%20Federation.md).

## Operating Notes

- **Respect connection limits**: Cloud SQL limits the number of concurrent connections, and every connection uses resources on both sides. Compute that scales out quickly can hit the limit, so the brief caps the loader's instance count and keeps a small pool per instance.[^sql-connections][^design-brief]
- **Connect from GKE with a sidecar**: On [Google Kubernetes Engine](Google%20Kubernetes%20Engine.md), the recommended setup runs the Auth Proxy as a sidecar container in the application's pod and supplies its identity through workload identity, not a key file.[^sql-connect-gke]
- **Keep analytics elsewhere**: The ledger serves small, transactional lookups. Analytical queries over events belong in [BigQuery](BigQuery.md).

## Related Notes

- Pattern: [Idempotent Event Consumer and Dead-Letter Queue](../patterns/Idempotent%20Event%20Consumer%20and%20Dead-Letter%20Queue.md)
- Concept: [Workload Identity Federation](../concepts/Workload%20Identity%20Federation.md)
- Source: [Event Analytics Design Brief Summary](../sources/Event%20Analytics%20Design%20Brief%20Summary.md)
- Synthesis: [Google Cloud Serverless Analytics Reference](../synthesis/Google%20Cloud%20Serverless%20Analytics%20Reference.md), [Production Readiness and Observability Checklist](../synthesis/Production%20Readiness%20and%20Observability%20Checklist.md)
