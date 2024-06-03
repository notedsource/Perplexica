# Cluster overview and creation

## Overview

To deploy Perplexica we need a very simple cluster.
There are two backend service that will be deployed to it, the Perplexica backend proper and the SearXNG search engine, more on those in deployments.MD.

A basic cluster with one preemptible node pool with fixed number of nodes is sufficient. NOTE: This will eventually have to be updated to autoscale nodes and pods with usage if platform grows and features based on this are widely used.

## Permissions
#
The follwoing Oauth scopes need to be added to the default cluster permissions to allow access to VertexAI. 
- `https://www.googleapis.com/auth/cloud-platform`

Additionally the service account associated with the cluster (This will be the default compute engine service account for the project unless explicitly changed) needs to be given following permissions:
- `Vertex AI Service Agent`

## Creation

Cluster creation is caputred by the `deploy/gcp/gke_cluster/main.tf` script. Terraform can be used to create the cluster and deployments or the same can be replicated using the gcloud command.

Following variables need to be populate/ passed in to Terraform:
- variable 
  - name = "project_id"
  - description = "The ID of the project in which resources will be deployed."

- variable 
  - name = "name"
  - description = "The GKE Cluster name"

- variable
  - name = "region"
  - description = "The GCP region to deploy to."

- variable 
  - name = "key_file"
  - description = "The path to the GCP service account key file."

NOTE: Exporting and using key file can be skipped by authenticaing gcloud with the properly permissioned account.

The service account whos key is used for cluster creation needs the following permissions:
- `Kubernetes Engine Admin` 
- `Compute Admin`
