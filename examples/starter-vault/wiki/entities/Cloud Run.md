---
title: "Cloud Run"
type: entity
description: "Google Cloud's managed platform for running containers as request-driven services and run-to-completion jobs without managing servers or clusters."
status: stable
tags:
  - gcp/compute
  - gcp/serverless
  - entity/product
sources:
  - id: design-brief
    resource: "/raw/event-analytics-design-brief.md"
    title: "Event Analytics Platform Design Brief"
    author: "team:cloud-platform"
  - id: run-overview
    resource: "https://cloud.google.com/run/docs/overview/what-is-cloud-run"
    title: "What is Cloud Run"
  - id: run-autoscaling
    resource: "https://cloud.google.com/run/docs/about-instance-autoscaling"
    title: "About instance autoscaling in Cloud Run services"
  - id: run-concurrency
    resource: "https://cloud.google.com/run/docs/about-concurrency"
    title: "Maximum concurrent requests for services"
  - id: run-rollouts
    resource: "https://cloud.google.com/run/docs/rollouts-rollbacks-traffic-migration"
    title: "Rollbacks, gradual rollouts, and traffic migration"
  - id: run-identity
    resource: "https://cloud.google.com/run/docs/securing/service-identity"
    title: "Introduction to service identity"
  - id: run-pubsub
    resource: "https://cloud.google.com/run/docs/tutorials/pubsub"
    title: "Use Pub/Sub with Cloud Run tutorial"
generated:
  by: "knowledge-compiler/1.2.0"
  at: "2026-11-18T00:00:00Z"
x-kc-complements:
  - "/wiki/concepts/Cloud Run Serverless Containers.md"
  - "/wiki/patterns/Revision Traffic Splitting and Canary Rollback.md"
  - "/wiki/entities/Google Kubernetes Engine.md"
---

# Cloud Run

**Cloud Run** is a managed compute platform that runs containers without requiring you to create a cluster or manage infrastructure. The resource types this vault refers to are *services*, which respond to HTTP requests and events, and *jobs*, which run tasks to completion. Cloud Run also offers worker pools for always-on, pull-based background work.[^run-overview]

## Key Capabilities

- **Request-driven autoscaling**: A service adds container instances as load rises and removes them as it falls, down to zero when the service is idle. Minimum and maximum instance limits bound that range.[^run-autoscaling]
- **Concurrency per instance**: One instance can serve many requests at the same time. The limit is configurable up to 1,000 concurrent requests per instance.[^run-concurrency]
- **Revisions and traffic control**: You choose which revisions receive traffic and in what percentages. That one mechanism covers gradual rollouts, traffic splits, and rollbacks.[^run-rollouts]
- **Per-service identity**: Each service runs as a service account. Client libraries fetch short-lived access tokens for it from the instance metadata server, so no key file ships with the container.[^run-identity]
- **Event delivery over HTTP**: A Pub/Sub push subscription can call a Cloud Run service directly, which turns an ordinary HTTP handler into an event consumer.[^run-pubsub]

## Role in the Reference Architecture

In the event analytics design brief, two of the three components run on Cloud Run.[^design-brief]

| Component | Trigger | Scales with | Related pattern |
| :--- | :--- | :--- | :--- |
| Ingest API | HTTPS requests from clients | Request concurrency | [Canary rollout](../patterns/Revision%20Traffic%20Splitting%20and%20Canary%20Rollback.md) |
| Loader | Push delivery from [Pub/Sub](Cloud%20PubSub.md) | Delivery rate | [Idempotent consumer](../patterns/Idempotent%20Event%20Consumer%20and%20Dead-Letter%20Queue.md) |

The brief keeps two ingest instances warm during business hours and lets the service scale to zero overnight. The third component, a stateful sessionizer, runs on [Google Kubernetes Engine](Google%20Kubernetes%20Engine.md) instead. The brief's rule is to start on Cloud Run and move a component only when it needs something Cloud Run does not offer for that workload shape. [Cloud Run vs GKE Autopilot Decision Matrix](../synthesis/Cloud%20Run%20vs%20GKE%20Autopilot%20Decision%20Matrix.md) generalizes that rule.

## Operating Notes

- **Keep services stateless**: Idle instances can be removed at any time, so anything that must survive belongs in an external store such as [Cloud SQL for PostgreSQL](Cloud%20SQL%20for%20PostgreSQL.md) or [BigQuery](BigQuery.md).
- **Protect downstream limits**: Fast scale-out multiplies database connections. The brief caps the loader's maximum instance count and keeps a small connection pool per instance.[^design-brief]
- **Acknowledge after the work is durable**: For push delivery, the HTTP status is the acknowledgement. Return success only once the write has succeeded. See [Event-Driven PubSub Pipelines](../concepts/Event-Driven%20PubSub%20Pipelines.md).
- **Roll out in steps**: The brief moves traffic to a new revision at 5, 25, 50, and 100 percent, with a hold at each step.[^design-brief] See [Revision Traffic Splitting and Canary Rollback](../patterns/Revision%20Traffic%20Splitting%20and%20Canary%20Rollback.md).
- **Continue the trace**: Pass the incoming trace context on every outbound call. See [OpenTelemetry Trace Propagation Across Services](../patterns/OpenTelemetry%20Trace%20Propagation%20Across%20Services.md).
- **Stay keyless**: The attached service identity is one case of the model described in [Workload Identity Federation](../concepts/Workload%20Identity%20Federation.md).

## Related Notes

- Concept: [Cloud Run Serverless Containers](../concepts/Cloud%20Run%20Serverless%20Containers.md)
- Source: [Event Analytics Design Brief Summary](../sources/Event%20Analytics%20Design%20Brief%20Summary.md)
- Synthesis: [Google Cloud Serverless Analytics Reference](../synthesis/Google%20Cloud%20Serverless%20Analytics%20Reference.md), [Production Readiness and Observability Checklist](../synthesis/Production%20Readiness%20and%20Observability%20Checklist.md)
