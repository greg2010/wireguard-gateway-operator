# wireguard-gateway-operator

[![CI](https://github.com/greg2010/wireguard-gateway-operator/actions/workflows/ci.yaml/badge.svg)](https://github.com/greg2010/wireguard-gateway-operator/actions/workflows/ci.yaml) [![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE) ![Go](https://img.shields.io/github/go-mod/go-version/greg2010/wireguard-gateway-operator)

A Kubernetes operator that runs WireGuard gateways on cloud VMs to give a private
or NAT'd cluster public ingress without exposing a cloud LoadBalancer of its own.
You apply a namespaced `Gateway` custom resource and the operator provisions a
dedicated gateway VM, dials it from inside the cluster, and forwards the public
TCP/UDP ports you list to your in-cluster Services. GCP is the cloud backend
implemented today.

Use it when a cluster cannot accept inbound connections directly: on-prem or
NAT'd clusters, a homelab behind a residential ISP, anything with outbound-only
egress. You still get stable public endpoints in front of cluster workloads.

## How it works

Each `Gateway` reconciles two halves. A Crossplane composition provisions a GCP
VM running WireGuard and nftables: it holds the public IP and opens the listed
ports. An in-cluster `gateway-link` Deployment peers with that VM and DNATs the
forwarded ports to the backend Services. Because the cluster only ever dials
outbound, no inbound firewall rule is needed cluster-side. When `dnsHostnames` is
set, the operator publishes a `DNSEndpoint` pointing those names at the VM's
public IP for external-dns to serve.

A minimal `Gateway`:

```yaml
apiVersion: wgnet.dev/v1alpha1
kind: Gateway
metadata:
  name: edge
  namespace: my-app
spec:
  gcp:
    projectID: my-gcp-project
    region: us-central1
    zone: us-central1-a
  forwards:
    - port: 443
      protocol: TCP
      service: my-app
```

This gives `my-app` a public endpoint on a cloud VM that forwards port 443 to the
in-cluster Service. See [Creating a gateway](#creating-a-gateway) for the full
spec.

```
            client
               │
               │  public internet
               ▼
┌─────────────────────────────┐
│  cloud gateway VM           │
│  public IP : port           │
│  WireGuard + nftables       │
└──────────────┬──────────────┘
               │  WireGuard tunnel
               │  (cluster dials outbound)
               ▼
┌─────────────────────────────┐
│  gateway-link Deployment    │
│  DNAT port → targetPort     │
└──────────────┬──────────────┘
               │  ClusterIP
               ▼
       backend Service ──▶ pods
```

## Cloud backends

Gateway-VM provisioning is backend-specific, and only GCP exists today.

| Backend | Status |
|---|---|
| GCP | Implemented |
| AWS | Not yet implemented |

## Prerequisites

| Requirement | Notes | Docs |
| --- | --- | --- |
| Kubernetes cluster + kubectl | Any conformant cluster; typically one that cannot expose its own LoadBalancer. | [kubectl](https://kubernetes.io/docs/tasks/tools/) |
| Helm | Installs Crossplane core and the operator chart. | [Helm](https://helm.sh/docs/intro/install/) |
| Crossplane | Installed in the cluster; realizes the gateway VM composition. | [Crossplane install](https://docs.crossplane.io/latest/get-started/install/) |
| GCP provider (installed) | The Upbound provider-gcp packages, installed via Crossplane's package mechanism. | [Crossplane providers](https://docs.crossplane.io/latest/packages/providers/) |
| GCP provider (configured) | A `ClusterProviderConfig` with `credentials.source=Secret` referencing a service-account key. | [Provider authentication](https://docs.upbound.io/manuals/packages/providers/authentication/) |
| GCP project + APIs | A project with billing and the compute, secretmanager, iam, and cloudresourcemanager APIs enabled. | [gcloud CLI](https://docs.cloud.google.com/sdk/docs/install) |
| GCP service-account key | A JSON key for a service account with the roles the composition needs, delivered as the Secret the `ClusterProviderConfig` references. | [Create SA key](https://docs.cloud.google.com/iam/docs/keys-create-delete) |

## Installation

Install the upstream dependencies in order: Crossplane core, the GCP providers
and pipeline functions, then credentials and a `ClusterProviderConfig`. Finish
with the operator. The charts under `k8s/infra/crossplane/`
(`crossplane-providers`, `crossplane-config`) are E2E test scaffolding: they pin
package versions and add a CRD-readiness gate Job for `make test-e2e`, and are
not a production install path.

**1. Crossplane core.**

```sh
helm install crossplane crossplane \
  --repo https://charts.crossplane.io/stable \
  -n crossplane-system --create-namespace --wait
```

**2. GCP providers and pipeline functions.**

```sh
kubectl apply -f - <<'EOF'
apiVersion: pkg.crossplane.io/v1beta1
kind: DeploymentRuntimeConfig
metadata:
  name: gcp-fast-poll
spec:
  deploymentTemplate:
    spec:
      selector: {}
      template:
        spec:
          containers:
            - name: package-runtime
              env:
                - name: PROVIDER_POLL
                  value: "30s"
---
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: provider-gcp-compute
spec:
  package: xpkg.upbound.io/upbound/provider-gcp-compute:v2
  runtimeConfigRef:
    name: gcp-fast-poll
---
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: provider-gcp-cloudplatform
spec:
  package: xpkg.upbound.io/upbound/provider-gcp-cloudplatform:v2
  runtimeConfigRef:
    name: gcp-fast-poll
---
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: provider-gcp-secretmanager
spec:
  package: xpkg.upbound.io/upbound/provider-gcp-secretmanager:v2
  runtimeConfigRef:
    name: gcp-fast-poll
---
apiVersion: pkg.crossplane.io/v1
kind: Function
metadata:
  name: function-go-templating
spec:
  package: xpkg.crossplane.io/crossplane-contrib/function-go-templating:v0.12.1
---
apiVersion: pkg.crossplane.io/v1
kind: Function
metadata:
  name: function-auto-ready
spec:
  package: xpkg.crossplane.io/crossplane-contrib/function-auto-ready:v0.6.5
EOF

kubectl wait --for=condition=Healthy provider.pkg.crossplane.io --all --timeout=5m
kubectl wait --for=condition=Healthy function.pkg.crossplane.io --all --timeout=5m
```

The providers track the floating `:v2` major channel, since Upbound publishes no
`:latest`. The functions pin an explicit version because crossplane-contrib
publishes no floating tag. Confirm current versions on the
[Upbound Marketplace](https://marketplace.upbound.io/) (providers) and the
[crossplane-contrib releases](https://github.com/crossplane-contrib) (functions).

The `gcp-fast-poll` DeploymentRuntimeConfig lowers the provider poll interval,
since the upstream default of 10m makes the multi-resource gateway provisioning
chain slow. Tune `PROVIDER_POLL`: lower is faster to provision at the cost of more
API calls. Do not declare a `provider-family-gcp` Provider explicitly: the leaf
providers pull the shared family in automatically, and declaring it duplicates
the family and breaks its RBAC.

**3. Credentials and ProviderConfig.** Load the service-account key as the
`crossplane-system/gcp-creds` Secret (key `credentials.json`). See
[Configuring GCP credentials](#configuring-gcp-credentials) for obtaining the key
and for the declarative loading paths. The direct form is:

```sh
kubectl create secret generic gcp-creds -n crossplane-system \
  --from-file=credentials.json=/path/to/gcp-key.json

kubectl apply -f - <<'EOF'
apiVersion: gcp.m.upbound.io/v1beta1
kind: ClusterProviderConfig
metadata:
  name: default
spec:
  projectID: YOUR_GCP_PROJECT_ID
  credentials:
    source: Secret
    secretRef:
      namespace: crossplane-system
      name: gcp-creds
      key: credentials.json
EOF
```

The `ClusterProviderConfig` name must be `default`: the gateway composition's GCP
managed resources reference `providerConfigRef.name: default`. It and the provider
CRDs must exist before any `Gateway` provisions.

**4. The operator.**

```sh
helm install wireguard-gateway-operator \
  oci://ghcr.io/greg2010/wireguard-gateway-operator/charts/wireguard-gateway-operator \
  --version 0.1.0 \
  -n wireguard-gateway-operator --create-namespace
```

The published chart pins the operator and link images, so no image values are
needed; override `operator.image` / `link.image` only if mirroring the images
elsewhere. The GCP project is set per Gateway via `spec.gcp.projectID`,
not on the chart. The two images are built from this repo's `Dockerfile`
(`make docker-build-operator` and `make docker-build`, override `OPERATOR_IMAGE` /
`IMAGE` to push registry-qualified tags).

## Configuring GCP credentials

The provider authenticates to GCP with a service-account JSON key. This section
covers minting that key; loading it as the Secret is step 4 below.

The exported key is long-lived and the scripts do not rotate it. Periodically
mint a replacement (`gcloud iam service-accounts keys create`), update the Secret,
and delete the old key.

1. Create a GCP project and enable the required APIs: compute, secretmanager,
   iam, cloudresourcemanager.
2. Create a service account and grant it the roles the composition needs
   (`compute.instanceAdmin.v1`, `compute.networkAdmin`, `compute.securityAdmin`,
   `iam.serviceAccountAdmin`, `iam.serviceAccountUser`, `secretmanager.admin`).
3. Create a JSON key for that service account.
4. Load the key into the cluster as the Secret above, using your cluster's
   declarative secret mechanism (External Secrets Operator, Sealed Secrets,
   or GitOps). The `ClusterProviderConfig` then reads it.

`scripts/setup-gcp-project.sh` performs step 1 (project and APIs),
`scripts/setup-gcp-sa.sh` performs step 2 (the service account and its roles),
and `scripts/get-gcp-creds.sh` performs step 3 (the key). All read configuration
from a `.env` file (see [.env.example](.env.example)). They produce the GCP-side
credential but intentionally do not load it into a cluster. That is step 4.

Reference: [create project](https://docs.cloud.google.com/resource-manager/docs/creating-managing-projects),
[enable APIs](https://docs.cloud.google.com/service-usage/docs/enable-disable),
[create service account](https://docs.cloud.google.com/iam/docs/service-accounts-create),
[create SA key](https://docs.cloud.google.com/iam/docs/keys-create-delete).

## Creating a gateway

Apply a `Gateway` in the namespace whose Services you want to expose. `provider`
defaults to `gcp`. Each forward names a public `port`, a `protocol`, the bare
in-cluster `service` name, and an optional `targetPort` (defaults to `port`).

`spec.gcp` holds the GCP placement: `projectID` (required), `region` (required),
`zone` (required), and the defaulted `machineType`, `image`, `diskSizeGB`,
`subnetCIDR`, `reservedIP`, and `spot`. `spec.wireguard` holds the tunnel
parameters, all defaulted: `listenPort` (the gateway VM's WireGuard UDP port,
range 1–65535), `subnet`, `gatewayAddress`, `linkAddress`, `keepalive`, `mtu`,
and `reconcileInterval`. An omitted `spec.wireguard` yields the standard tunnel.

```yaml
apiVersion: wgnet.dev/v1alpha1
kind: Gateway
metadata:
  name: edge
  namespace: my-app
spec:
  gcp:
    projectID: my-gcp-project
    region: us-central1
    zone: us-central1-a
    machineType: e2-small
  forwards:
    - port: 443
      protocol: TCP
      service: my-app
      targetPort: 8443
    - port: 80
      protocol: TCP
      service: my-app
      targetPort: 8081
  wireguard:
    listenPort: 51820
  dnsHostnames:
    - edge.example.com
```

```sh
kubectl apply -f gateway.yaml
kubectl get gateway -n my-app
```

```
NAME   ADDRESS         READY
edge   203.0.113.42    True
```

Forward validation is enforced at apply time and rejected by the Kubernetes API
server:

- Each forward's `(port, protocol)` combination must be unique.
- A UDP forward must not use `spec.wireguard.listenPort`.
- At most 64 forwards per Gateway.

The `ADDRESS` column is the gateway VM's public IP, mirrored onto
`status.address` once provisioning completes; `READY` reflects the `Ready`
condition. With `dnsHostnames` set and external-dns running, the listed names
resolve to that IP.

## Cross-namespace forwards

A forward targets a Service in the Gateway's own namespace by default. To forward
into a different namespace, set `forwards[].namespace`, and the target namespace
must opt in by carrying the label `wgnet.dev/allow-gateway-ingress: "true"`. This
consent gate prevents a Gateway owner from exposing another tenant's Service to
the public internet.

```sh
kubectl label namespace other-ns wgnet.dev/allow-gateway-ingress=true
```

```yaml
  forwards:
    - port: 8080
      protocol: TCP
      service: api
      namespace: other-ns
```

Backend Services of type `ClusterIP` and `NodePort` are supported (both carry a
routable ClusterIP to DNAT to). `ExternalName` and headless Services are
rejected: the Gateway reports `Ready=False` with reason `UnsupportedServiceType`.

## Development

Run `make test` for the full suite (unit, integration, e2e) or the per-suite
targets `make test-unit` / `make test-integration` / `make test-e2e`. The e2e
suite self-provisions a kind cluster, the full Crossplane stack, and a real GCP
gateway, so it requires the GCP configuration above. Local development needs
[Go](https://go.dev/doc/install), [kind](https://kind.sigs.k8s.io/docs/user/quick-start/),
and a container runtime — [Docker](https://docs.docker.com/engine/install/) or
[Podman](https://podman.io/docs/installation).

## License

Apache License 2.0. See [LICENSE](LICENSE).
