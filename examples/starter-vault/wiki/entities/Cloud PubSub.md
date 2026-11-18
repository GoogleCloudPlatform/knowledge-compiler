---
title: "Cloud PubSub"
type: entity
description: "Pub/Sub, Google Cloud's asynchronous messaging service that decouples event producers from consumers through topics and push, pull, or export subscriptions."
status: stable
tags:
  - gcp/messaging
  - architecture/event-driven
  - entity/product
sources:
  - id: pubsub-overview
    resource: "https://cloud.google.com/pubsub/docs/overview"
    title: "What is Pub/Sub?"
  - id: pubsub-subscriptions
    resource: "https://cloud.google.com/pubsub/docs/subscription-overview"
    title: "Subscription overview"
  - id: pubsub-push
    resource: "https://cloud.google.com/pubsub/docs/push"
    title: "Push subscriptions"
  - id: pubsub-ordering
    resource: "https://cloud.google.com/pubsub/docs/ordering"
    title: "Order messages"
  - id: pubsub-dead-letter
    resource: "https://cloud.google.com/pubsub/docs/dead-letter-topics"
    title: "Dead-letter topics"
  - id: pubsub-exactly-once
    resource: "https://cloud.google.com/pubsub/docs/exactly-once-delivery"
    title: "Exactly-once delivery"
  - id: pubsub-replay
    resource: "https://cloud.google.com/pubsub/docs/replay-overview"
    title: "Replay and purge messages with seek"
  - id: design-brief
    resource: "/raw/event-analytics-design-brief.md"
    title: "Event Analytics Platform Design Brief"
    author: "team:cloud-platform"
generated:
  by: "knowledge-compiler/1.2.0"
  at: "2026-11-18T00:00:00Z"
complements:
  - "[[Event-Driven PubSub Pipelines]]"
  - "[[Idempotent Event Consumer and Dead-Letter Queue]]"
  - "[[Cloud Run]]"
---

# Cloud PubSub

**Pub/Sub** is Google Cloud's asynchronous messaging service. It decouples the services that produce messages from the services that process them: publishers send messages to a topic, and subscribers receive them through subscriptions.[^pubsub-overview] The product name is written Pub/Sub. This note is titled `Cloud PubSub` only because a file name cannot contain a slash.

## Delivery Model

A subscription's type decides how messages reach the consumer.[^pubsub-subscriptions]

| Subscription type | How messages arrive | Consumer in the design brief |
| :--- | :--- | :--- |
| Push | Pub/Sub sends each message as an HTTPS request to a configured endpoint | Loader on [[Cloud Run]] |
| Pull | The subscriber client requests messages from Pub/Sub | Sessionizer on [[Google Kubernetes Engine|GKE]] |
| Export | Pub/Sub writes messages directly to a destination such as a [[BigQuery]] table | Considered, not adopted |

With push delivery, the endpoint acknowledges a message by returning an HTTP success status. Any other response tells Pub/Sub to send the message again.[^pubsub-push]

## Key Capabilities

- **At-least-once by default**: Every subscription type delivers each message at least once, with no ordering guarantee unless you enable one. Consumers have to tolerate duplicates.[^pubsub-subscriptions]
- **Ordering keys**: When ordering is enabled on a subscription, messages that share an ordering key and are published in the same region arrive in the order they were published. Publish throughput per ordering key is limited.[^pubsub-ordering]
- **Dead-letter topics**: After a configured maximum number of delivery attempts (between 5 and 100), Pub/Sub forwards the message to a separate topic. The count is approximate, so treat it as a threshold and not an exact promise.[^pubsub-dead-letter]
- **Exactly-once delivery**: Pull subscriptions can enable exactly-once delivery within a cloud region. Push and export subscriptions do not support it.[^pubsub-exactly-once]
- **Replay**: Seeking a subscription to a snapshot or a timestamp replays previously acknowledged messages or purges a backlog in bulk.[^pubsub-replay]

## Role in the Reference Architecture

In the design brief, Pub/Sub is the durable buffer between the ingest API and its consumers.[^design-brief]

- **One topic, two subscriptions**: `events-raw` feeds a push subscription for the loader and a pull subscription, ordered by session ID, for the sessionizer.
- **Success means published**: The ingest API returns a success status only after the publish call is acknowledged. The no-loss goal rests on this.
- **Five attempts, then aside**: Both subscriptions forward a message to a dead-letter topic after five failed deliveries, and a separate subscription keeps those messages for inspection and replay.
- **Trace context in attributes**: The publisher copies W3C trace context into message attributes so consumers can continue the trace. See [[OpenTelemetry Trace Propagation Across Services]].

The trade-offs between push and pull are covered in [[Event-Driven PubSub Pipelines]]. The consumer-side contract is covered in [[Idempotent Event Consumer and Dead-Letter Queue]].

## Operating Notes

- **Design for redelivery first**: The brief relies on an idempotency key and leaves exactly-once delivery as an open question for the pull subscription.[^design-brief]
- **Keep ordering keys fine-grained**: A key that carries too much traffic becomes a bottleneck. The brief flags hot keys as a risk that needs a load test.[^design-brief]
- **Watch the dead-letter topic**: Messages that land there are the ones the pipeline could not process. See [[Production Readiness and Observability Checklist]].
- **Publish and subscribe without keys**: Publishers and subscribers authenticate with runtime identities. See [[Workload Identity Federation]].

## Related Notes

- Concept: [[Event-Driven PubSub Pipelines]]
- Pattern: [[Idempotent Event Consumer and Dead-Letter Queue]]
- Source: [[Event Analytics Design Brief Summary]]
- Synthesis: [[Google Cloud Serverless Analytics Reference]]
