package k8s

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/util/retry"
)

// agnhostImage is the canonical Kubernetes e2e test image. Its netexec /hostname path
// returns the serving pod's name, which the probes use as the data-path marker.
const agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.53"

// EchoFixtures names a TCP (HTTP) and a UDP echo Service. The probes' retry budget
// absorbs the backing Deployments' startup, so no readiness wait is done.
type EchoFixtures struct {
	TCPService string
	// TCPPort is the port the TCP echo Service publishes, which is what a forward
	// targets. The Service remaps it to a different pod port.
	TCPPort    int
	UDPService string
	UDPPort    int
}

// echo fixture constants. The container ports match the agnhost netexec flags.
const (
	echoTCPName      = "gateway-echo-tcp"
	echoUDPName      = "gateway-echo-udp"
	echoNodePortName = "gateway-echo-nodeport"
	echoXNSName      = "gateway-echo-xns"
	echoTCPPort      = 8080
	echoUDPPort      = 8081

	// Remapped from echoTCPPort so the data path covers a Service whose targetPort
	// differs from its port: the link must egress to the pod port, not the published one.
	echoTCPTargetPort = 9080
)

// EchoBackend is a single HTTP echo Service the link can DNAT a forward to, returned by
// the helpers that deploy one backend rather than the pair EchoFixtures carries.
type EchoBackend struct {
	Namespace string
	// Service is the bare Service name; the operator builds the FQDN from it and
	// Namespace.
	Service string
	Port    int
}

// DeployEchoFixtures creates the TCP and UDP echo Deployments and Services in ns. It
// does not wait for Available; the data-path probes retry long enough to cover startup.
func (c *Client) DeployEchoFixtures(ctx context.Context, ns string) (EchoFixtures, error) {
	tcpArgs := []string{"netexec", fmt.Sprintf("--http-port=%d", echoTCPTargetPort)}
	udpArgs := []string{"netexec", fmt.Sprintf("--udp-port=%d", echoUDPPort), "--http-port=0"}

	if err := c.applyEcho(ctx, ns, echoTCPName, echoTCPPort, echoTCPTargetPort, corev1.ProtocolTCP, corev1.ServiceTypeClusterIP, tcpArgs, echoOptions{}); err != nil {
		return EchoFixtures{}, err
	}
	if err := c.applyEcho(ctx, ns, echoUDPName, echoUDPPort, echoUDPPort, corev1.ProtocolUDP, corev1.ServiceTypeClusterIP, udpArgs, echoOptions{}); err != nil {
		return EchoFixtures{}, err
	}

	return EchoFixtures{
		TCPService: echoTCPName,
		TCPPort:    echoTCPPort,
		UDPService: echoUDPName,
		UDPPort:    echoUDPPort,
	}, nil
}

// DeployNodePortEcho fronts an HTTP echo with a NodePort Service, exercising the
// NodePort acceptance path. Its name is distinct so it coexists with the fixtures.
func (c *Client) DeployNodePortEcho(ctx context.Context, ns string) (EchoBackend, error) {
	args := []string{"netexec", fmt.Sprintf("--http-port=%d", echoTCPPort)}
	if err := c.applyEcho(ctx, ns, echoNodePortName, echoTCPPort, echoTCPPort, corev1.ProtocolTCP, corev1.ServiceTypeNodePort, args, echoOptions{}); err != nil {
		return EchoBackend{}, err
	}
	return EchoBackend{Namespace: ns, Service: echoNodePortName, Port: echoTCPPort}, nil
}

// DeployEchoInNamespaceOnNode creates ns with nsLabels and a ClusterIP echo pinned to node; an
// empty node leaves placement to the scheduler. Labels go on at creation so the consent label
// precedes the Gateway reconcile, and Local mode needs the cross-namespace backend on the same
// worker, since every forward must have a ready endpoint on the holder node.
func (c *Client) DeployEchoInNamespaceOnNode(ctx context.Context, ns string, nsLabels map[string]string, node string) (EchoBackend, error) {
	nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: nsLabels}}
	if _, err := c.typed.CoreV1().Namespaces().Create(ctx, nsObj, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return EchoBackend{}, fmt.Errorf("create namespace %s: %w", ns, err)
	}
	args := []string{"netexec", fmt.Sprintf("--http-port=%d", echoTCPPort)}
	if err := c.applyEcho(ctx, ns, echoXNSName, echoTCPPort, echoTCPPort, corev1.ProtocolTCP, corev1.ServiceTypeClusterIP, args, echoOptions{node: node}); err != nil {
		return EchoBackend{}, err
	}
	return EchoBackend{Namespace: ns, Service: echoXNSName, Port: echoTCPPort}, nil
}

// DeployEchoBackend creates a caller-named ClusterIP HTTP echo for a runtime forward. It
// does not wait for Available; the data-path probes cover pod startup.
func (c *Client) DeployEchoBackend(ctx context.Context, ns, name string) (EchoBackend, error) {
	args := []string{"netexec", fmt.Sprintf("--http-port=%d", echoTCPPort)}
	if err := c.applyEcho(ctx, ns, name, echoTCPPort, echoTCPPort, corev1.ProtocolTCP, corev1.ServiceTypeClusterIP, args, echoOptions{}); err != nil {
		return EchoBackend{}, err
	}
	return EchoBackend{Namespace: ns, Service: name, Port: echoTCPPort}, nil
}

// DeployEchoOnNode pins a ClusterIP HTTP echo to node, which a Local-mode test needs
// because every forward's backend must have a ready endpoint on the holder's node. It
// does not wait for Available.
func (c *Client) DeployEchoOnNode(ctx context.Context, ns, name, node string) (EchoBackend, error) {
	args := []string{"netexec", fmt.Sprintf("--http-port=%d", echoTCPPort)}
	if err := c.applyEcho(ctx, ns, name, echoTCPPort, echoTCPPort, corev1.ProtocolTCP, corev1.ServiceTypeClusterIP, args, echoOptions{node: node}); err != nil {
		return EchoBackend{}, err
	}
	return EchoBackend{Namespace: ns, Service: name, Port: echoTCPPort}, nil
}

// DeployUDPEchoOnNode pins a ClusterIP UDP echo to node, the Local shard's UDP backend.
// It does not wait for Available.
func (c *Client) DeployUDPEchoOnNode(ctx context.Context, ns, name, node string) (EchoBackend, error) {
	args := []string{"netexec", fmt.Sprintf("--udp-port=%d", echoUDPPort), "--http-port=0"}
	if err := c.applyEcho(ctx, ns, name, echoUDPPort, echoUDPPort, corev1.ProtocolUDP, corev1.ServiceTypeClusterIP, args, echoOptions{node: node}); err != nil {
		return EchoBackend{}, err
	}
	return EchoBackend{Namespace: ns, Service: name, Port: echoUDPPort}, nil
}

// RepinEchoToNode rewrites the pod template's nodeName so the rollout replaces the pod
// on node. It retries on conflict so a concurrent status write cannot lose the change.
func (c *Client) RepinEchoToNode(ctx context.Context, ns, name, node string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		dep, err := c.typed.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get echo deployment %s/%s: %w", ns, name, err)
		}
		dep.Spec.Template.Spec.NodeName = node
		if _, err := c.typed.AppsV1().Deployments(ns).Update(ctx, dep, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("repin echo deployment %s/%s to %s: %w", ns, name, node, err)
		}
		return nil
	})
}

// echoOptions carries applyEcho's optional knobs. The zero value is the common case:
// a pod the scheduler places wherever it fits.
type echoOptions struct {
	// node pins the pod through spec.nodeName, which is what a Local-mode test needs to
	// place a backend on a chosen worker.
	node string
}

// applyEcho publishes port and DNATs it to targetPort, where the container listens, so
// the caller's args must agree. Idempotent, so Start may re-run in a reused namespace.
func (c *Client) applyEcho(ctx context.Context, ns, name string, port, targetPort int, proto corev1.Protocol, svcType corev1.ServiceType, args []string, opts echoOptions) error {
	labels := map[string]string{"app": name}
	replicas := int32(1)

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					NodeName: opts.node,
					Containers: []corev1.Container{{
						Name:  "echo",
						Image: agnhostImage,
						Args:  args,
						Ports: []corev1.ContainerPort{{
							ContainerPort: int32(targetPort),
							Protocol:      proto,
						}},
					}},
				},
			},
		},
	}
	if _, err := c.typed.AppsV1().Deployments(ns).Create(ctx, dep, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create echo deployment %s/%s: %w", ns, name, err)
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: corev1.ServiceSpec{
			Type:     svcType,
			Selector: labels,
			Ports: []corev1.ServicePort{{
				Port:       int32(port),
				TargetPort: intstr.FromInt(targetPort),
				Protocol:   proto,
			}},
		},
	}
	if _, err := c.typed.CoreV1().Services(ns).Create(ctx, svc, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create echo service %s/%s: %w", ns, name, err)
	}
	return nil
}
