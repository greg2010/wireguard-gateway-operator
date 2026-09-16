package crossplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	fnv1 "github.com/crossplane/function-sdk-go/proto/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

var (
	providerSchemaOnce sync.Once
	providerSchemaEnv  *envtest.Environment
	providerSchema     client.Client
	providerSchemaErr  error
)

func TestApplyDryRunRejectsSchemaMismatches(t *testing.T) {
	if os.Getenv("GATEWAY_INTEGRATION") == "" {
		t.Skip("set GATEWAY_INTEGRATION to run the composition integration test")
	}
	for _, tt := range []struct {
		name, key, want string
		resource        map[string]any
	}{
		{name: "secret selector name", key: "secret-version", want: "secretSelector.name", resource: map[string]any{"apiVersion": "secretmanager.gcp.m.upbound.io/v1beta1", "kind": "SecretVersion", "spec": map[string]any{"forProvider": map[string]any{"secretSelector": map[string]any{"name": "x"}}}}},
		{name: "backend map", key: "backend-service", want: "backend", resource: map[string]any{"apiVersion": "compute.gcp.m.upbound.io/v1beta1", "kind": "RegionBackendService", "spec": map[string]any{"forProvider": map[string]any{"backend": map[string]any{"group": "x"}}}}},
		{name: "backend service object", key: "forwarding-rule", want: "backendService", resource: map[string]any{"apiVersion": "compute.gcp.m.upbound.io/v1beta1", "kind": "ForwardingRule", "spec": map[string]any{"forProvider": map[string]any{"backendService": map[string]any{"name": "x"}}}}},
		{name: "unvendored disk", key: "disk", want: "no provider CRD vendored", resource: map[string]any{"apiVersion": "compute.gcp.m.upbound.io/v1beta1", "kind": "Disk", "spec": map[string]any{}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := applyDryRun(context.Background(), providerSchemaClient(t), tt.key, tt.resource)
			if err == nil {
				t.Fatal("applyDryRun returned nil error")
			}
			t.Logf("server error: %v", err)
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want containing %q", err, tt.want)
			}
		})
	}
}

func TestProviderCRDsMatchPinnedVersion(t *testing.T) {
	stamp := strings.TrimSpace(readRepoFile(t, "test/integration/crossplane/testdata/provider-crds/VERSION"))
	tags := providerPackageTags(t, readRepoFile(t, "k8s/infra/crossplane/crossplane-providers/values.yaml"))
	gotPackages := make([]string, 0, len(tags))
	for _, tag := range tags {
		gotPackages = append(gotPackages, tag.name)
	}
	sort.Strings(gotPackages)
	wantPackages := []string{"provider-family-gcp", "provider-gcp-cloudplatform", "provider-gcp-compute", "provider-gcp-secretmanager"}
	if !slices.Equal(gotPackages, wantPackages) {
		t.Fatalf("provider packages = %q, want %q", gotPackages, wantPackages)
	}
	for _, tt := range tags {
		t.Run(fmt.Sprintf("pinned tag of %s matches the vendored version", tt.name), func(t *testing.T) {
			if tt.tag != stamp {
				t.Errorf("provider tag = %q, want stamp %q", tt.tag, stamp)
			}
		})
	}
}

func providerSchemaClient(t *testing.T) client.Client {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Fatalf("KUBEBUILDER_ASSETS unset; run through make test-integration")
	}
	providerSchemaOnce.Do(func() {
		dir := filepath.Join(repoRoot(t), "test", "integration", "crossplane", "testdata", "provider-crds")
		options := envtest.CRDInstallOptions{Paths: []string{dir}, ErrorIfPathMissing: true}
		if err := envtest.ReadCRDFiles(&options); err != nil {
			providerSchemaErr = err
			return
		}
		for _, crd := range options.CRDs {
			if crd.Spec.Conversion != nil && crd.Spec.Conversion.Strategy == apiextensionsv1.WebhookConverter {
				t.Logf("set conversion strategy to None for %s", crd.Name)
				crd.Spec.Conversion.Strategy = apiextensionsv1.NoneConverter
			}
		}
		options.Paths = nil
		providerSchemaEnv = &envtest.Environment{CRDInstallOptions: options}
		cfg, err := providerSchemaEnv.Start()
		if err != nil {
			providerSchemaErr = err
			return
		}
		providerSchema, providerSchemaErr = client.New(cfg, client.Options{})
	})
	if providerSchemaErr != nil {
		t.Fatalf("start provider schema envtest: %v", providerSchemaErr)
	}
	return providerSchema
}

func applyDryRun(ctx context.Context, c client.Client, key string, resource map[string]any) error {
	obj := &unstructured.Unstructured{Object: resource}
	obj.SetName(dryRunName(key))
	gvk := obj.GroupVersionKind()
	mapping, err := c.RESTMapper().RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		if _, ok := errors.AsType[*meta.NoKindMatchError](err); ok {
			return fmt.Errorf("no provider CRD vendored for %s: add its CRD name to the provider-crds Makefile target: %w", gvk, err)
		}
		return fmt.Errorf("%s (%s): resolve REST mapping: %w", key, gvk, err)
	}
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		obj.SetNamespace("default")
	}
	data, err := json.Marshal(obj.Object)
	if err != nil {
		return err
	}
	if err := c.Patch(ctx, obj, client.RawPatch(types.ApplyPatchType, data), client.DryRunAll, client.ForceOwnership, client.FieldOwner("composition-schema-check")); err != nil {
		return fmt.Errorf("%s (%s): %w", key, gvk, err)
	}
	return nil
}

func assertComposedResourcesMatchProviderSchemas(t *testing.T, resp *fnv1.RunFunctionResponse) {
	t.Helper()
	keys := make([]string, 0, len(resp.GetDesired().GetResources()))
	for key := range resp.GetDesired().GetResources() {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := applyDryRun(ctx, providerSchemaClient(t), key, resp.GetDesired().GetResources()[key].GetResource().AsMap())
		cancel()
		if err != nil {
			t.Errorf("%v", err)
		}
	}
}

func dryRunName(key string) string {
	var name strings.Builder
	for _, r := range strings.ToLower(key) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			name.WriteRune(r)
		} else {
			name.WriteByte('-')
		}
	}
	normalized := strings.Trim(name.String(), "-")
	if len(normalized) > 253 {
		normalized = normalized[:253]
	}
	return normalized
}

type providerTag struct{ name, tag string }

func providerPackageTags(t *testing.T, data string) []providerTag {
	t.Helper()
	var value any
	if err := yaml.Unmarshal([]byte(data), &value); err != nil {
		t.Fatalf("parse provider values: %v", err)
	}
	var tags []providerTag
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case string:
			if strings.HasPrefix(v, "xpkg.upbound.io/upbound/provider-") {
				repoTag := strings.TrimPrefix(v, "xpkg.upbound.io/upbound/")
				name, tag, ok := strings.Cut(repoTag, ":")
				if !ok {
					t.Fatalf("provider package has no tag: %s", v)
				}
				tags = append(tags, providerTag{name, tag})
			}
		case map[string]any:
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(value)
	return tags
}
