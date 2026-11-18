---
title: "Cloud Run vs GKE Autopilot Decision Matrix"
type: synthesis
description: "Criteria for placing a containerized workload on Cloud Run or GKE Autopilot, with a decision table and an illustrative workload mix."
status: stable
tags:
  - gcp/compute
  - synthesis/decision-matrix
  - architecture/containers
sources:
  - id: gke-and-cloud-run
    resource: "https://cloud.google.com/kubernetes-engine/docs/concepts/gke-and-cloud-run"
    title: "GKE and Cloud Run"
  - id: run-overview
    resource: "https://cloud.google.com/run/docs/overview/what-is-cloud-run"
    title: "What is Cloud Run"
  - id: run-autoscaling
    resource: "https://cloud.google.com/run/docs/about-instance-autoscaling"
    title: "About instance autoscaling in Cloud Run services"
  - id: run-request-timeout
    resource: "https://cloud.google.com/run/docs/configuring/request-timeout"
    title: "Configure request timeout for services"
  - id: run-rollouts
    resource: "https://cloud.google.com/run/docs/rollouts-rollbacks-traffic-migration"
    title: "Rollbacks, gradual rollouts, and traffic migration"
  - id: run-service-identity
    resource: "https://cloud.google.com/run/docs/securing/service-identity"
    title: "Introduction to service identity"
  - id: gke-autopilot-overview
    resource: "https://cloud.google.com/kubernetes-engine/docs/concepts/autopilot-overview"
    title: "GKE Autopilot overview"
  - id: gke-workload-identity
    resource: "https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity"
    title: "About Workload Identity Federation for GKE"
generated:
  by: "knowledge-compiler/1.2.0"
  at: "2026-11-18T00:00:00Z"
extends:
  - "[[Google Cloud Serverless Analytics Reference]]"
complements:
  - "[[Cloud Run Serverless Containers]]"
  - "[[GKE Autopilot]]"
---

# Cloud Run vs GKE Autopilot Decision Matrix

[[Cloud Run]] and [[Google Kubernetes Engine]] in Autopilot mode both run the same container image without node management by the team. The decision is how much of the Kubernetes API the workload needs. Cloud Run is best suited to stateless, request-driven and event-driven services, while GKE is best suited to stateful applications, complex microservices, and cases where deep control over Kubernetes is essential.[^gke-and-cloud-run]

## Decision Table

| Criterion | Lean toward [[Cloud Run Serverless Containers|Cloud Run]] | Lean toward [[GKE Autopilot|Autopilot]] | Related note |
| :--- | :--- | :--- | :--- |
| Infrastructure to operate | No cluster to create or manage[^run-overview] | Google manages nodes, while the team stays responsible for the core Kubernetes aspects[^gke-autopilot-overview][^gke-and-cloud-run] | [[GKE Autopilot|Autopilot concept]] |
| Workload shape | Stateless services, functions, and jobs that run to completion[^gke-and-cloud-run] | Stateful applications and complex microservices with specific resource needs[^gke-and-cloud-run] | [[Google Cloud Serverless Analytics Reference|Reference architecture]] |
| Kubernetes API | Not needed by the workload | Operators, custom resources, or existing manifests are part of the design | [[Google Kubernetes Engine|GKE]] |
| Scaling | Request-driven, down to zero instances when idle[^run-autoscaling] | Replica counts follow CPU, memory, or custom metrics | [[Cloud Run Serverless Containers|Serverless containers]] |
| Request shape | HTTP, gRPC, or WebSocket requests that finish within the timeout, 5 minutes by default and 60 at most[^run-overview][^run-request-timeout] | Custom TCP or UDP protocols, or work that outlives a request timeout | [[Cloud Run]] |
| Event consumption | Push delivery to a service, or a worker pool for always-on pull consumers[^run-overview] | Consumers that also need Kubernetes scheduling, storage, or operators | [[Event-Driven PubSub Pipelines|Pub/Sub pipelines]] |
| State | State is kept in [[Cloud SQL for PostgreSQL|Cloud SQL]] or [[BigQuery]] | Pods need stable identities or a persistent volume for each replica | [[Idempotent Event Consumer and Dead-Letter Queue|Idempotent consumer]] |
| Rollouts | Built-in revision traffic splitting[^run-rollouts] | Rolling updates, with canaries added through a gateway or delivery pipeline | [[Revision Traffic Splitting and Canary Rollback|Canary rollback]] |
| Identity | A service account attached to each service[^run-service-identity] | Kubernetes ServiceAccounts referenced directly in IAM policies[^gke-workload-identity] | [[Workload Identity Federation|Keyless identity]] |
| Tracing | Not a differentiator: OpenTelemetry spans are exported the same way | Not a differentiator: OpenTelemetry spans are exported the same way | [[OpenTelemetry Trace Propagation Across Services|Trace propagation]] |

## Illustrative Workload Mix

The chart below is a planning example for a platform team that sorts its container workloads by class. The percentages are illustrative, not measured data. Replace them with your own inventory before using the chart in a review.

```mermaid
pie title Illustrative workload mix by class
  "Stateless HTTP APIs" : 40
  "Event-driven consumers" : 20
  "Scheduled and batch jobs" : 15
  "Stateful services" : 15
  "Operators and custom agents" : 10
```

| Workload class | Usual home | Reason |
| :--- | :--- | :--- |
| Stateless HTTP APIs | [[Cloud Run Serverless Containers|Cloud Run]] service | Request-driven scaling and revision traffic splitting cover the need |
| Event-driven consumers | [[Cloud Run Serverless Containers|Cloud Run]] service or worker pool | Push and pull consumers of [[Cloud PubSub|Pub/Sub]] run without a cluster |
| Scheduled and batch jobs | [[Cloud Run Serverless Containers|Cloud Run]] job | The task runs to completion and then releases its instances |
| Stateful services | [[GKE Autopilot|Autopilot]] | Stable pod identity and persistent volumes are Kubernetes features |
| Operators and custom agents | [[GKE Autopilot|Autopilot]] | Custom resources and controllers require the Kubernetes API |

In this example, the first three classes, 75 percent of workloads, lean toward Cloud Run and the remaining 25 percent lean toward Autopilot.

## Applied to the Design Brief

[[Event Analytics Design Brief Summary]] places three components with the same criteria:

| Component | Runtime | Deciding factors |
| :--- | :--- | :--- |
| Ingest API | [[Cloud Run]] | Stateless, request-driven, and bursty, with scaling to zero overnight |
| Loader | [[Cloud Run]] | Stateless, one push request for each message from [[Cloud PubSub|Pub/Sub]] |
| Sessionizer | [[Google Kubernetes Engine|GKE]] in [[GKE Autopilot|Autopilot]] mode | In-memory session state, a long-lived streaming pull connection, and scaling on backlog |

The brief leaves one question open: Cloud Run worker pools, which handle always-on pull workloads, were not evaluated for the sessionizer.[^run-overview] If they meet its state and scaling needs, that placement should be revisited.

## Decision Rules

- **Start with the simpler runtime**: Place a new stateless workload on Cloud Run and move it only when it needs something Cloud Run does not offer for that workload shape. The same image runs on both platforms, and the Cloud Run Admin API v1 is designed to be compatible with the Kubernetes API, which keeps a later move small.[^gke-and-cloud-run]
- **Treat Kubernetes features as hard requirements**: Custom resources, operators, per-replica persistent volumes, and non-HTTP protocols point to Autopilot regardless of team preference.
- **Use both when the system has both shapes**: Running some workloads on each platform is a supported strategy.[^gke-and-cloud-run] [[Google Cloud Serverless Analytics Reference]] does exactly that, with ingestion on Cloud Run and stateful processing on Autopilot.
- **Keep the cross-cutting controls identical**: Identity, tracing, and idempotent event handling should not depend on the runtime. [[Production Readiness and Observability Checklist]] applies to both.
- **Revisit when the shape changes**: A Cloud Run service that has grown always-on instances and several sidecars, or a Deployment that is one stateless container scaled by request load, is a sign the workload sits on the wrong side of the table.

## Related Notes

- [[Cloud Run Serverless Containers]] and [[GKE Autopilot]] describe each runtime on its own terms.
- [[Revision Traffic Splitting and Canary Rollback]] details the Cloud Run rollout model referenced in the table.
- [[Workload Identity Federation]] covers keyless identity for both runtimes.
