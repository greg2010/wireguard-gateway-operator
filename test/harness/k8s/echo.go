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

// agnhostImage is the canonical Kubernetes e2e test image. Its `netexec`
// subcommand serves HTTP on --http-port (the /hostname path returns the
// serving pod's name, the marker the TCP data-path assertion checks) and echoes
// UDP datagrams on --udp-port.
const agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.53"

// EchoFixtures deploys a TCP (HTTP) echo Service and a UDP echo Service into ns
// and waits for the backing Deployments to become Available. The link DNATs
// beacon ports to these Services' DNS names.
type EchoFixtures struct {
	// TCPService is the in-cluster DNS name of the HTTP echo Service.
	TCPService string
	// TCPPort is the Service port the HTTP echo listens on.
	TCPPort int
	// UDPService is the in-cluster DNS name of the UDP echo Service.
	UDPService string
	// UDPPort is the Service port the UDP echo listens on.
	UDPPort int
}

// echo fixture constants. The container ports match the agnhost netexec flags.
const (
	echoTCPName = "cyno-echo-tcp"
	echoUDPName = "cyno-echo-udp"
	echoTCPPort = 8080
	echoUDPPort = 8081
)

// DeployEchoFixtures creates the TCP and UDP echo Deployments and Services in
// ns and returns their addresses once both Deployments are Available. The
// returned Service names are short (in-namespace) DNS names; the link resolves
// them within the same namespace.
func (c *Client) DeployEchoFixtures(ctx context.Context, ns string) (EchoFixtures, error) {
	tcpArgs := []string{"netexec", fmt.Sprintf("--http-port=%d", echoTCPPort)}
	udpArgs := []string{"netexec", fmt.Sprintf("--udp-port=%d", echoUDPPort), "--http-port=0"}

	if err := c.applyEcho(ctx, ns, echoTCPName, echoTCPPort, corev1.ProtocolTCP, tcpArgs); err != nil {
		return EchoFixtures{}, err
	}
	if err := c.applyEcho(ctx, ns, echoUDPName, echoUDPPort, corev1.ProtocolUDP, udpArgs); err != nil {
		return EchoFixtures{}, err
	}

	return EchoFixtures{
		TCPService: echoTCPName,
		TCPPort:    echoTCPPort,
		UDPService: echoUDPName,
		UDPPort:    echoUDPPort,
	}, nil
}

// applyEcho creates one echo Deployment+Service. Idempotent on the
// already-exists path so re-running Start in a reused namespace is safe.
func (c *Client) applyEcho(ctx context.Context, ns, name string, port int, proto corev1.Protocol, args []string) error {
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
