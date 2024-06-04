# Ingress overview and creation

## Overview

Creating an ingress to a deployment in the cluster allows us to have a reserved IP address that won't change, setting up a SSL Cert. to secure traffic and setting up rules to route traffic. Additionally the Ingress creation sets up the necessary DNS entries for us.

Ingress is comprised of a Frontend and Backend (this is different than those of the application).

- Frontend

  - SSL Certs.
  - Routing rules - What endpoint groups to route traffic to based on path rules

- Backend
  - Zone endpoint groups - Regional instances of the ingress that route external traffic to the internal cluster network

NOTE:
By default ingress connections are setup to time out at 30secs. as they are intended for shortlived "REST" traffic, these should be increased as the Perplexica backend utilizes websocket connections, more on this below.

## Creation

Currently this was done manually (some complexity around doing this in the Terraform scripts), should probably be captured in a TF script eventually.

In Cloud console, `https://console.cloud.google.com/kubernetes/discovery`:

- Select backend service we want to route to
- Create ingress
- In the config "wizard" you can create and SSL certs. and setup domain and routing rules

NOTE: Ingress expects root route `/` on the service to return `HTTP 200` as a health check, otherwise it will not see the services as healthy and traffic will not be routed there. This can also be changed to a different path in the ingress configuration if needed.

### Updating ingress config

#### Setup

- Authenticate with gcloud to a service account with correct permissions
- Configure kubectl access `gcloud container clusters get-credentials CLUSTER_NAME --region=COMPUTE_REGION`
  - More info at `https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl`

### The Ingress configuration needs to be updated to increase the connection timeout, this is a two step process.

- Create a `Backend config`
- Copy `example-backend-confg.yaml` to `backend-config.yaml`
- Edit the YAML to update timeout settings to desired values
- Create config on the cluster `kubectl apply -f backend-config.yaml`

- Apply this config to the target loadblancer
  - Download the current loadblancer service config `kubectl get svc backend-service -o yaml > backend-svc.yaml`
  - Edit the `backend-svc.yaml` and add the annotation below to the `metadata` >> `annotations` section
    - Annotation: `cloud.google.com/backend-config: '{"ports": {"3001":"perplexica-config"}}'`, replace config name if changed.
    - Example of updated config found in `example-backend-confg.yaml`
  - Patch the loadbalnacer service config with new settings `kubectl patch svc backend-service --patch-file backend-svc.json`
