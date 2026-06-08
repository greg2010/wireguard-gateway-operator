package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	wgnetv1alpha1 "github.com/greg2010/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// testEnv bundles a running envtest control plane and a client wired to the
// operator's scheme, shared by the controller tests in this package.
type testEnv struct {
	env    *envtest.Environment
	cfg    *rest.Config
	client client.Client
	scheme *runtime.Scheme
}

// gatewayCRDPath is the controller-gen-emitted Gateway CRD, loaded into the test
// API server so the typed client can create Gateways.
func gatewayCRDPath() string {
	return filepath.Join("..", "..", "k8s", "charts", "wireguard-gateway-operator", "templates", "crds")
}

// setupEnvtest starts a control plane with the Gateway CRD plus minimal XGatewayGCP and
// DNSEndpoint CRDs and returns a client on the operator scheme. It skips when
// KUBEBUILDER_ASSETS is unset.
func setupEnvtest(t *testing.T) *testEnv {
	t.Helper()

	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run `make envtest` and export it to exercise the envtest path")
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(wgnetv1alpha1.AddToScheme(scheme))

	env := &envtest.Environment{
		Scheme:                scheme,
		ErrorIfCRDPathMissing: true,
		CRDInstallOptions: envtest.CRDInstallOptions{
			Paths: []string{gatewayCRDPath()},
			CRDs:  []*apiextensionsv1.CustomResourceDefinition{minimalXGatewayGCPCRD(), minimalXGatewayNetworkCRD(), minimalDNSEndpointCRD()},
		},
	}

	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	})

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	return &testEnv{env: env, cfg: cfg, client: c, scheme: scheme}
}

// preserveUnknownProps is the open object schema the minimal CRDs use so the
// operator's arbitrary spec/status fields round-trip without a typed schema.
func preserveUnknownProps() *apiextensionsv1.JSONSchemaProps {
	yes := true
	return &apiextensionsv1.JSONSchemaProps{
		Type:                   "object",
		XPreserveUnknownFields: &yes,
	}
}

// minimalXGatewayGCPCRD is a namespaced CRD matching the composite's GVK with an
// open schema and a status subresource, enough for the reconciler to create the
// composite and read a patched status.
func minimalXGatewayGCPCRD() *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "xgatewaygcps.infra.wgnet.dev"},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "infra.wgnet.dev",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:     "XGatewayGCP",
				ListKind: "XGatewayGCPList",
				Plural:   "xgatewaygcps",
				Singular: "xgatewaygcp",
			},
			Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name:    "v1alpha1",
				Served:  true,
				Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: preserveUnknownProps(),
				},
				Subresources: &apiextensionsv1.CustomResourceSubresources{
					Status: &apiextensionsv1.CustomResourceSubresourceStatus{},
				},
			}},
		},
	}
}

// minimalXGatewayNetworkCRD is a namespaced CRD matching the shared-network composite's
// GVK with an open schema and a status subresource, enough for the reconciler to apply
// the singleton network and for the refcount teardown to read and delete it.
func minimalXGatewayNetworkCRD() *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "xgatewaynetworks.infra.wgnet.dev"},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "infra.wgnet.dev",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:     "XGatewayNetwork",
				ListKind: "XGatewayNetworkList",
				Plural:   "xgatewaynetworks",
				Singular: "xgatewaynetwork",
			},
			Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name:    "v1alpha1",
				Served:  true,
				Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: preserveUnknownProps(),
				},
				Subresources: &apiextensionsv1.CustomResourceSubresources{
					Status: &apiextensionsv1.CustomResourceSubresourceStatus{},
				},
			}},
		},
	}
}

// minimalDNSEndpointCRD is a namespaced CRD matching external-dns's DNSEndpoint
// GVK with an open schema, so the operator's DNS builder can create it.
func minimalDNSEndpointCRD() *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dnsendpoints.externaldns.k8s.io",
			// The API server gates *.k8s.io groups behind an approval annotation;
			// external-dns ships this on its real CRD.
			Annotations: map[string]string{
				"api-approved.kubernetes.io": "https://github.com/kubernetes-sigs/external-dns/pull/2007",
			},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "externaldns.k8s.io",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:     "DNSEndpoint",
				ListKind: "DNSEndpointList",
				Plural:   "dnsendpoints",
				Singular: "dnsendpoint",
			},
			Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name:    "v1alpha1",
				Served:  true,
				Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: preserveUnknownProps(),
				},
			}},
		},
	}
}

// eventually polls cond until it returns true or the deadline elapses, failing
// the test with msg on timeout. envtest has no informer cache here, so a poll
// loop is the simplest way to await asynchronous reconcile effects.
func eventually(ctx context.Context, t *testing.T, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s: context done: %v", msg, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("timed out waiting for %s", msg)
}
