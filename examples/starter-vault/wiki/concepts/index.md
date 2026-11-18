# Core Concepts

OKF v0.3 subdirectory index for `wiki/concepts/` (see [Master Index](../../index.md) and [Wiki Index](../index.md)).

- [BigQuery Partition Pruning Check](BigQuery%20Partition%20Pruning%20Check.md): Attested BigQuery SQL computation that ranks recent single-table queries on partitioned tables by the share of the table they scanned, exposing partition filters that fail to prune.
- [BigQuery Partitioning and Clustering](BigQuery%20Partitioning%20and%20Clustering.md): Table layout techniques in BigQuery that divide data by a partitioning column and sort storage blocks by clustering columns, so filtered queries read less data and finish faster.
- [Cloud Run Serverless Containers](Cloud%20Run%20Serverless%20Containers.md): Request-driven container platform that runs stateless services and run-to-completion jobs on Google Cloud, scaling from zero without cluster operations.
- [Event-Driven PubSub Pipelines](Event-Driven%20PubSub%20Pipelines.md): Design principles for decoupling producers and consumers with Pub/Sub topics and subscriptions, covering pull and push delivery, ordering keys, acknowledgement, dead-lettering, and backpressure.
- [GKE Autopilot](GKE%20Autopilot.md): Mode of Google Kubernetes Engine in which Google Cloud provisions, scales, upgrades, and hardens the nodes, so teams operate Kubernetes workloads rather than virtual machines.
- [Legacy Unpartitioned Daily Batch Table](Legacy%20Unpartitioned%20Daily%20Batch%20Table.md): Deprecated BigQuery layout in which a nightly batch job appends each day's export to one unpartitioned table, forcing full-table scans; superseded by partitioned and clustered tables.
- [Workload Identity Federation](Workload%20Identity%20Federation.md): Keyless authentication in which workloads trade platform-issued OIDC, SAML, or Kubernetes credentials for short-lived Google Cloud tokens instead of storing service account JSON keys.
