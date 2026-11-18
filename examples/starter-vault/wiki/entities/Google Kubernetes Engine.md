---
title: "Google Kubernetes Engine"
type: entity
description: "Google Cloud's managed Kubernetes service, offered in Autopilot and Standard modes, for workloads that need the full Kubernetes API."
status: stable
tags:
  - gcp/compute
  - gcp/kubernetes
  - entity/product
sources:
  - id: gke-overview
    resource: "https://cloud.google.com/kubernetes-engine/docs/concepts/kubernetes-engine-overview"
    title: "GKE overview"
  - id: gke-autopilot
    resource: "https://cloud.google.com/kubernetes-engine/docs/concepts/autopilot-overview"
    title: "GKE Autopilot overview"
  - id: gke-release-channels
    resource: "https://cloud.google.com/kubernetes-engine/docs/concepts/release-channels"
    title: "About release channels"
  - id: gke-hpa
    resource: "https://cloud.google.com/kubernetes-engine/docs/concepts/horizontalpodautoscaler"
    title: "Horizontal Pod autoscaling"
  - id: gke-workload-identity
    resource: "https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity"
    title: "About Workload Identity Federation for GKE"
  - id: design-brief
    resource: "/raw/event-analytics-design-brief.md"
    title: "Event Analytics Platform Design Brief"
    author: "team:cloud-platform"
generated:
  by: "knowledge-compiler/1.2.0"
  at: "2026-11-18T00:00:00Z"
complements:
  - "[[GKE Autopilot]]"
  - "[[Cloud Run]]"
extends:
  - "[[Workload Identity Federation]]"
---

# Google Kubernetes Engine

**Google Kubernetes Engine (GKE)** is Google Cloud's managed Kubernetes service. Google operates the cluster control plane, and you deploy workloads through the standard Kubernetes API.[^gke-overview]

## Modes of Operation

| Aspect | Autopilot | Standard |
| :--- | :--- | :--- |
| Node management | Google provisions, scales, and upgrades nodes | You create and manage node pools |
| What you configure | Pod specifications and resource requests | Pods, plus node machine types and scaling |
| Baseline configuration | Google's best practices applied by default | Chosen by the cluster operator |
| Typical fit | Teams that want Kubernetes APIs without node operations | Workloads that need manual control of nodes |

Autopilot is the recommended way to use GKE.[^gke-autopilot] The mode is covered in depth in [[GKE Autopilot]].

## Key Capabilities

- **Managed upgrades**: A cluster enrolls in a release channel (Rapid, Regular, Stable, or Extended) and receives Kubernetes versions at the pace that channel defines.[^gke-release-channels]
- **Autoscaling on workload signals**: Horizontal Pod autoscaling changes the replica count in response to CPU, memory, custom metrics, or external metrics such as the backlog of a message subscription.[^gke-hpa]
- **Keyless workload identity**: Workload Identity Federation for GKE lets IAM policies grant Kubernetes workloads access to Google Cloud APIs without service account key files. It applies the model in [[Workload Identity Federation]] to pods inside a cluster.[^gke-workload-identity]
- **Full Kubernetes surface**: Deployments, StatefulSets, Jobs, and custom resources work as they do on any Kubernetes cluster.[^gke-overview]

## Role in the Reference Architecture

The design brief runs one component on GKE: the sessionizer, deployed to an Autopilot cluster.[^design-brief] Three properties moved it off [[Cloud Run]]:

1. It holds open sessions in memory between messages.
2. It keeps a long-lived streaming pull connection to [[Cloud PubSub|Pub/Sub]] and does not receive one HTTP request per message.
3. It scales on subscription backlog, not on request rate.

The brief also records an open question: Cloud Run worker pools were not evaluated, and the decision should be revisited if they meet the same needs.[^design-brief] [[Cloud Run vs GKE Autopilot Decision Matrix]] compares the two runtimes criterion by criterion.

## Operating Notes

- **Size from measurements**: In Autopilot mode you configure resource requests, not nodes, so requests that match real usage matter more than they do when spare node capacity hides a bad estimate.
- **Shut down cleanly**: On a termination signal, a pull subscriber should stop receiving, finish in-flight messages, and acknowledge them. Anything left unacknowledged is delivered again. See [[Event-Driven PubSub Pipelines]] and [[Idempotent Event Consumer and Dead-Letter Queue]].
- **Reach databases without keys**: Pods connect to [[Cloud SQL for PostgreSQL]] with their workload identity.
- **Continue the trace**: Pull consumers read trace context from message attributes. See [[OpenTelemetry Trace Propagation Across Services]].

## Related Notes

- Concepts: [[GKE Autopilot]], [[Workload Identity Federation]]
- Source: [[Event Analytics Design Brief Summary]]
- Synthesis: [[Google Cloud Serverless Analytics Reference]], [[Production Readiness and Observability Checklist]]
