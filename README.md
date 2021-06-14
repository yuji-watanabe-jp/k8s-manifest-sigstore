# Kubernetes Manifest Sigstore
kubectl sigstore signing plugin

> :warning: Still under developement, not ready for production use yet!

This kubectl subscommand plugin enables both developper to sign k8s manifest yaml files and application owner to verify the origin of configurations and the integrity of deployed manifests on cluster. 

## Installation

plugin is a standalone executable file `kubectl-sigstore`. To install the plugin, move this executable file to any location on your PATH.

## Usage (annotation)

### Sign a k8s yaml manifest file

`kubectl sigstore sign foo.yaml`

### Sign k8s yaml manifest files

`kubectl sigstore sign foo.yaml`

### Verify a k8s yaml manifest file

`kubectl sigstore verify foo.yaml`

### Create resource with a k8s yaml manifest file after verifying signature

`kubectl sigstore apply-after-verify -f foo.yaml -n ns1`

### Verify a k8s yaml manifest of deployed resource with signature

`kubectl sigstore verify-resource deploy foo -n ns1`

## Usage (bundle image on OCI registry)

A bundle image reference is added in metadata.annotations in manifest yaml by default. 
It is not added when `-no-annotation` option is supplied

### Sign k8s yaml manifest files as bundle OCI image

`kubectl sigstore sign -dir bar -image bundle-bar:dev`

### Verify a k8s yaml manifest file

`kubectl sigstore verify foo.yaml -image bundle-bar:dev`

### Create resource with a k8s yaml manifest file after verifying signature

`kubectl sigstore apply-after-verify -f foo.yaml -n ns1 -image bundle-bar:dev`

### Verify a k8s yaml manifest of deployed resource with signature

`kubectl sigstore verify-resource cm foo -n ns1 -image bundle-bar:dev`

