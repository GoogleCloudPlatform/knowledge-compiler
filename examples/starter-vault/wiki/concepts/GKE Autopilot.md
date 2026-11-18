---
title: "GKE Autopilot"
type: concept
description: "Mode of Google Kubernetes Engine in which Google Cloud provisions, scales, upgrades, and hardens the nodes, so teams operate Kubernetes workloads rather than virtual machines."
status: stable
tags:
  - gcp/kubernetes
  - architecture/containers
  - operations/managed-infrastructure
sources:
  - id: autopilot-overview
    resource: "https://cloud.google.com/kubernetes-engine/docs/concepts/autopilot-overview"
    title: "GKE Autopilot overview"
  - id: autopilot-comparison
    resource: "https://cloud.google.com/kubernetes-engine/docs/resources/autopilot-standard-feature-comparison"
    title: "Compare features in Autopilot and Standard clusters"
  - id: autopilot-requests
    resource: "https://cloud.google.com/kubernetes-engine/docs/concepts/autopilot-resource-requests"
    title: "Resource requests in Autopilot"
  - id: autopilot-security
    resource: "https://cloud.google.com/kubernetes-engine/docs/concepts/autopilot-security"
    title: "GKE Autopilot security measures"
  - id: gke-release-channels
    resource: "https://cloud.google.com/kubernetes-engine/docs/concepts/release-channels"
    title: "About release channels"
generated:
  by: "knowledge-compiler/1.2.0"
  at: "2026-11-18T00:00:00Z"
x-kc-extends:
  - "/wiki/entities/Google Kubernetes Engine.md"
x-kc-complements:
  - "/wiki/concepts/Cloud Run Serverless Containers.md"
---

# GKE Autopilot

GKE Autopilot is a mode of operation for [Google Kubernetes Engine](../entities/Google%20Kubernetes%20Engine.md) in which Google Cloud runs the nodes. It sizes capacity from the resource requests in your Pod specifications and manages node configuration, autoscaling, upgrades, and security constraints. Teams keep the full Kubernetes API but own workloads rather than virtual machines.[^autopilot-overview][^autopilot-comparison]

## Operating Model

- **Pod-Centric Capacity**: Autopilot configures nodes from the requests your containers declare. It assigns default requests to containers that omit them and enforces minimum and maximum values that depend on the compute class or hardware a Pod asks for, so explicit requests keep scheduling predictable.[^autopilot-requests]
- **Hardened by Default**: Autopilot blocks privileged containers (apart from verified partner tooling) and SSH access to nodes, and enables Workload Identity Federation for GKE so Pods cannot read sensitive node metadata. Pods reach Google Cloud APIs with short-lived tokens instead of exported keys, as covered in [Workload Identity Federation](Workload%20Identity%20Federation.md).[^autopilot-security]
- **Managed Upgrades**: Every Autopilot cluster is enrolled in a release channel, Regular by default, and Google Cloud upgrades the control plane and nodes within the maintenance windows and exclusions you set.[^autopilot-overview][^gke-release-channels]
- **Regional and Shielded**: Autopilot clusters are regional, with Shielded GKE Nodes and Secure Boot preconfigured.[^autopilot-comparison]

## Compute Selection Guide

| Criterion | [Cloud Run](Cloud%20Run%20Serverless%20Containers.md) | GKE Autopilot |
| :--- | :--- | :--- |
| Unit of deployment | Service revision or job | Pod, Deployment, StatefulSet, or Job |
| API surface | Cloud Run Admin API and service YAML | Full Kubernetes API, CRDs, and operators |
| Scaling signal | Request concurrency and CPU, down to zero | Pod autoscalers, with nodes provisioned from Pod requests |
| State | External stores only | StatefulSets with persistent volumes |
| Networking controls | Ingress settings, IAM invoker checks, VPC egress | Services, Gateway API, and network policies |
| Workload identity | Service account attached to the service | Kubernetes ServiceAccount through Workload Identity Federation for GKE |
| Best fit | Stateless APIs, push handlers, batch jobs | Long-running services, sidecar-heavy Pods, Kubernetes-native tooling |

The [Cloud Run vs GKE Autopilot Decision Matrix](../synthesis/Cloud%20Run%20vs%20GKE%20Autopilot%20Decision%20Matrix.md) turns these criteria into a decision path. Many platforms run both. In the [Event Analytics Design Brief Summary](../sources/Event%20Analytics%20Design%20Brief%20Summary.md), the ingest API and loader run on [Cloud Run](../entities/Cloud%20Run.md), while the sessionizer runs on Autopilot because it holds open sessions in memory, keeps a long-lived streaming pull connection, and scales on subscription backlog rather than request rate.

## Related Notes

- [Google Kubernetes Engine](../entities/Google%20Kubernetes%20Engine.md)
- [Cloud Run Serverless Containers](Cloud%20Run%20Serverless%20Containers.md)
- [Cloud Run vs GKE Autopilot Decision Matrix](../synthesis/Cloud%20Run%20vs%20GKE%20Autopilot%20Decision%20Matrix.md)
- [Workload Identity Federation](Workload%20Identity%20Federation.md)
- [Event-Driven PubSub Pipelines](Event-Driven%20PubSub%20Pipelines.md)
- [Google Cloud Serverless Analytics Reference](../synthesis/Google%20Cloud%20Serverless%20Analytics%20Reference.md)
- [Event Analytics Design Brief Summary](../sources/Event%20Analytics%20Design%20Brief%20Summary.md)
