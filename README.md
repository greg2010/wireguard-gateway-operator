# wireguard-gateway-operator

A Kubernetes operator that gives a private or NAT'd cluster public ingress
without exposing a cloud LoadBalancer of its own. You apply a namespaced
`Gateway` custom resource; the operator provisions a dedicated GCP WireGuard
gateway VM, dials it from inside the cluster, and forwards public TCP/UDP ports
to your pods.

## What it does

For each `Gateway`, the operator reconciles two halves:

| Half | Mechanism | Responsibility |
| --- | --- | --- |
| Cloud gateway VM | Crossplane `XGateway` composite | A per-Gateway GCP VM with a public IP, opening the configured ports and terminating a WireGuard tunnel. |
| In-cluster link | `gateway-link` Deployment | Dials the gateway VM over WireGuard (cluster always connects outbound) and nftables-DNATs the public ports to in-cluster pods. |

The cluster only ever connects outbound, so no inbound firewall rule is needed
on the cluster side. Public traffic arriving at the VM is forwarded through the
tunnel and DNAT'd to the target pods. When `dnsHostnames` is set, the operator
publishes a `DNSEndpoint` pointing those names at the gateway's public IP for
external-dns to serve.

## Prerequisites

| Requirement | Notes |
| --- | --- |
| A Kubernetes cluster | Typically private or NAT'd — one that cannot expose its own LoadBalancer. |
| Crossplane | The `XGateway` composite is realized by a Crossplane composition. |
| Upbound GCP provider | Provisions the gateway VM and its supporting GCP resources. |
| external-dns | Optional. Required only if you set `dnsHostnames`; it serves the published `DNSEndpoint`. |

A GCP project with billing enabled, reachable by the Upbound provider's
credentials, hosts the gateway VMs.

## Install

```
helm install wireguard-gateway-operator \
  k8s/charts/wireguard-gateway-operator \
  -n wireguard-gateway-operator --create-namespace
```

## Usage

Apply a `Gateway` in the namespace whose pods you want to expose:

```yaml
apiVersion: wgnet.dev/v1alpha1
kind: Gateway
metadata:
  name: edge
  namespace: my-app
spec:
  gcp:
    region: us-central1
    zone: us-central1-a
    machineType: e2-micro
  forwards:
    - port: 443
      protocol: TCP
      service: my-app
      targetPort: 8443
    - port: 51820
      protocol: UDP
      service: my-app
  dnsHostnames:
    - edge.example.com
```

The operator provisions the gateway VM, brings up the tunnel, and forwards each
listed port to in-cluster pods. With `dnsHostnames` set and external-dns
running, the listed names resolve to the gateway's public IP.

## License

Apache License 2.0. See [LICENSE](LICENSE).
