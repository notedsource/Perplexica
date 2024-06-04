# Deployments overview and creation

## Overview

Two images are deployed to the Perplexica cluster.

- Perplexica Backend

- SearXNG Backend

Each one is setup with only 1 replica, this should be updated to autoscale in the future.

Each of these deployments sits behind a Loadbalencer, both of them can be internal if ingress will be used for outside access.

The Perplexica backend requires the address of a SearXNG service as a configuration parameter, the address of the SearXNG Loadbalencer should be used for this.

NOTE: 
An external Loadbalencer can be used provide direct access to of the deployments via a public IP address. These IPs are not perament and will be reassigned if the Loadbalencer is recreated, a GKE Ingress should be preferred to allow reserved IPs, SSL connections and rounting rules.

### Topology diagram
----------------------------------------------------------------------------------------------------------------
                                ┌─────────────────────────────────┐                                    
                                │ DNS (perplexica.notedsource.io) │                                    
                                └───────────────┬─────────────────┘                                    
                                                │                                                      
                                         ┌──────┴───────┐                                              
                                         │ GKE Ingress  │                                              
                                         └──────┬───────┘                                              
                                                │                                                      
                             ┌──────────────────┘                                                      
                             │                                                                         
                    ┌────────┴────────┐                   ┌──────────┬────Cluster Network──┬─────────  
                    │   Application   │                   │          │                     │           
                    │    External     │                   │   ┌──────┴───────┐       ┌─────┴────────┐  
                    │   Loadbalencer  │                   │   │   External   │       │  Internal    │  
                    └──┬──────────┬───┘                   │   │   Service    │       │  Service     │  
                       │          │                       │   │ Loadbalencer │       │ Loadbalencer │  
    ┌────────────────┬─┘          └──┬───────────────┐    │   └──────┬───────┘       └──────┬───────┘  
    │    Frontend    │               │    Backend    │    │          │                      │          
    └────┬────────┬──┘               └───────┬───────┘    │  ┌───────┴────────┐     ┌───────┴────────┐ 
         │        │                          │            │  │                │     │                │ 
 ┌───────┴────┐ ┌─┴───────┐         ┌───────┬┴───────┬┐   │  │   Perplexica   │     │   SearXNG      │ 
 │Path routing│ │SSL Cert.│         │Network│endpoint└┼┐  │  │   deployment   │     │   deployment   │ 
 │   rules    │ └─────────┘         ├┐   Groups       │┼──┘  │                │     │                │ 
 └────────────┘                     └┼────────────────┼│     └───────┬────────┘     └───────┬────────┘ 
                                     └─────────────────┘             │                      │          
                                                                 ┌┬──┴─┬─┐              ┌┬──┴─┬─┐      
                                                                 ││Pods│┼┼┐             ││Pods│┼┼┐     
                                                                 └┼────┼┼┼│             └┼────┼┼┼│     
                                                                  └───────┘              └───────┘     
----------------------------------------------------------------------------------------------------------------

## Creation

Deployments and Loadbalencer creation is captured in `deploy/gcp/main.tf` Terraform script.

A make file `deploy/gcp/Makefile` captures all the commands to build both images, create the cluster and publish the deployments. Only things required are:
- To configure the enviorment by copying `sample.env` to `.env` and filling out the required info there.
- Either use gcloud to auth to a service accout with needed permissions or provide a path in `.env` to a service accout key file.
