package gcpmembers

import (
	"context"
	"os"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// testEnv provides cached and uncached clients backed by envtest.
type testEnv struct {
	env      *envtest.Environment
	cfg      *rest.Config
	client   client.Client
	uncached client.Reader
}

// setupEnvtest starts the minimal CRDs needed for member cleanup tests.
func setupEnvtest(t *testing.T) *testEnv {
	t.Helper()

	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run `make envtest` and export it to exercise the envtest path")
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	env := &envtest.Environment{
		Scheme:                scheme,
		ErrorIfCRDPathMissing: true,
		CRDInstallOptions: envtest.CRDInstallOptions{
			CRDs: []*apiextensionsv1.CustomResourceDefinition{
				minimalXGatewayGCPCRD(),
				minimalSecretManagerCRD("secrets", "Secret", "SecretList"),
				minimalSecretManagerCRD("secretversions", "SecretVersion", "SecretVersionList"),
				minimalSecretManagerCRD("secretiammembers", "SecretIAMMember", "SecretIAMMemberList"),
			},
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

	cl, err := cluster.New(cfg, func(o *cluster.Options) { o.Scheme = scheme })
	if err != nil {
		t.Fatalf("new cluster: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		if err := cl.Start(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("cluster.Start: %v", err)
		}
	}()
	if !cl.GetCache().WaitForCacheSync(ctx) {
		t.Fatalf("cache did not sync")
	}

	return &testEnv{env: env, cfg: cfg, client: cl.GetClient(), uncached: cl.GetAPIReader()}
}

func preserveUnknownProps() *apiextensionsv1.JSONSchemaProps {
	yes := true
	return &apiextensionsv1.JSONSchemaProps{
		Type:                   "object",
		XPreserveUnknownFields: &yes,
	}
}

// minimalXGatewayGCPCRD supplies the composite CRD required by envtest.
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

// minimalSecretManagerCRD supplies one managed resource CRD required by envtest.
func minimalSecretManagerCRD(plural, kind, listKind string) *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: plural + ".secretmanager.gcp.m.upbound.io"},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "secretmanager.gcp.m.upbound.io",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:     kind,
				ListKind: listKind,
				Plural:   plural,
				Singular: plural,
			},
			Scope: apiextensionsv1.ClusterScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name:    "v1beta1",
				Served:  true,
				Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: preserveUnknownProps(),
				},
			}},
		},
	}
}
