package k8s

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// agnhostImage is the canonical Kubernetes e2e test image. Its netexec subcommand
// serves HTTP on --http-port (the /hostname path returns the serving pod's name, the
// data-path marker) and echoes UDP datagrams on --udp-port.
const agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.53"

// EchoFixtures names a TCP (HTTP) echo Service and a UDP echo Service created in
// ns. The link DNATs gateway ports to these Services' DNS names; the probes' retry
// budget absorbs the backing Deployments' startup, so no readiness wait is done.
type EchoFixtures struct {
	TCPService string
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
)

// EchoBackend is a single HTTP echo Service the link can DNAT a forward to. It
// is the return shape for the standalone echo helpers (NodePort, cross-namespace)
// that deploy one backend rather than the TCP+UDP pair EchoFixtures carries.
type EchoBackend struct {
	Namespace string
	// Service is the bare Service name; the operator builds the FQDN from it and
	// Namespace.
	Service string
	Port    int
}

// DeployEchoFixtures creates the TCP and UDP echo Deployments and Services in ns and
// returns their in-namespace addresses. It does not wait for Available; the data-path
// probes retry long enough to cover pod startup.
func (c *Client) DeployEchoFixtures(ctx context.Context, ns string) (EchoFixtures, error) {
	tcpArgs := []string{"netexec", fmt.Sprintf("--http-port=%d", echoTCPPort)}
	udpArgs := []string{"netexec", fmt.Sprintf("--udp-port=%d", echoUDPPort), "--http-port=0"}

	if err := c.applyEcho(ctx, ns, echoTCPName, echoTCPPort, corev1.ProtocolTCP, corev1.ServiceTypeClusterIP, tcpArgs); err != nil {
		return EchoFixtures{}, err
	}
	if err := c.applyEcho(ctx, ns, echoUDPName, echoUDPPort, corev1.ProtocolUDP, corev1.ServiceTypeClusterIP, udpArgs); err != nil {
		return EchoFixtures{}, err
	}

	return EchoFixtures{
		TCPService: echoTCPName,
		TCPPort:    echoTCPPort,
		UDPService: echoUDPName,
		UDPPort:    echoUDPPort,
	}, nil
}

// DeployNodePortEcho creates an HTTP echo Deployment fronted by a NodePort Service
// in ns and returns its address, exercising the NodePort service-type acceptance
// path. Its name is distinct from the ClusterIP fixtures so both can coexist.
func (c *Client) DeployNodePortEcho(ctx context.Context, ns string) (EchoBackend, error) {
	args := []string{"netexec", fmt.Sprintf("--http-port=%d", echoTCPPort)}
	if err := c.applyEcho(ctx, ns, echoNodePortName, echoTCPPort, corev1.ProtocolTCP, corev1.ServiceTypeNodePort, args); err != nil {
		return EchoBackend{}, err
	}
	return EchoBackend{Namespace: ns, Service: echoNodePortName, Port: echoTCPPort}, nil
}

// DeployEchoInNamespace creates ns with nsLabels and deploys a ClusterIP echo into
// it, the cross-namespace forward fixture. The namespace is created with the labels
// in one shot so the consent label is present before the Gateway reconciles.
func (c *Client) DeployEchoInNamespace(ctx context.Context, ns string, nsLabels map[string]string) (EchoBackend, error) {
	nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: nsLabels}}
	if _, err := c.typed.CoreV1().Namespaces().Create(ctx, nsObj, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return EchoBackend{}, fmt.Errorf("create namespace %s: %w", ns, err)
	}
	args := []string{"netexec", fmt.Sprintf("--http-port=%d", echoTCPPort)}
	if err := c.applyEcho(ctx, ns, echoXNSName, echoTCPPort, corev1.ProtocolTCP, corev1.ServiceTypeClusterIP, args); err != nil {
		return EchoBackend{}, err
	}
	return EchoBackend{Namespace: ns, Service: echoXNSName, Port: echoTCPPort}, nil
}

// DeployEchoBackend creates a ClusterIP HTTP echo named name in ns and returns its
// address, the caller-named dedicated backend the lifecycle subtests attach a runtime
// forward to. It does not wait for Available; the data-path probes cover pod startup.
func (c *Client) DeployEchoBackend(ctx context.Context, ns, name string) (EchoBackend, error) {
	args := []string{"netexec", fmt.Sprintf("--http-port=%d", echoTCPPort)}
	if err := c.applyEcho(ctx, ns, name, echoTCPPort, corev1.ProtocolTCP, corev1.ServiceTypeClusterIP, args); err != nil {
		return EchoBackend{}, err
	}
	return EchoBackend{Namespace: ns, Service: name, Port: echoTCPPort}, nil
}

// applyEcho creates one echo Deployment+Service of the given Service type.
// Idempotent on the already-exists path so re-running Start in a reused namespace
// is safe.
func (c *Client) applyEcho(ctx context.Context, ns, name string, port int, proto corev1.Protocol, svcType corev1.ServiceType, args []string) error {
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
					Containers: []corev1.Container{{
						Name:  "echo",
						Image: agnhostImage,
						Args:  args,
						Ports: []corev1.ContainerPort{{
							ContainerPort: int32(port),
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
				TargetPort: intstr.FromInt(port),
				Protocol:   proto,
			}},
		},
	}
	if _, err := c.typed.CoreV1().Services(ns).Create(ctx, svc, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create echo service %s/%s: %w", ns, name, err)
	}
	return nil
}
