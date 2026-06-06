// Package crossplane exercises the shipped GCP XGateway composition template
// against the real function-go-templating function image over gRPC.
//
// The test does not stand up Crossplane or a Kubernetes API server: it drives
// the function's FunctionRunnerService directly, the same contract Crossplane
// invokes per reconcile. This isolates the template logic (the part this repo
// owns) from the rest of the rendering pipeline.
package crossplane

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	fnv1 "github.com/crossplane/function-sdk-go/proto/v1"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

// functionImage is the prebuilt function-go-templating function. Keep this
// digest in sync with k8s/infra/crossplane/crossplane-providers/values.yaml.
const functionImage = "xpkg.crossplane.io/crossplane-contrib/function-go-templating@sha256:86f02d0b0e22725015d4be7f4d25bebee47e27300f496ad55630bc64be5f8c9a"

const (
	// functionPort is the plaintext gRPC port function-go-templating listens on
	// when started with --insecure.
	functionPort = "9443/tcp"

	// xrName is the composite resource name every case in this suite uses. The
	// function keys observed composed resources by this value via the
	// crossplane.io/composite label, so observed fixtures must carry it too.
	xrName = "xgateway-smoke"

	// testRegion is the region every fixture XR requests.
	testRegion = "us-central1"

	// reservedAddr is the external IP the observed Address reports once
	// allocated. The reservedIP case asserts it surfaces on the instance
	// accessConfig natIp and on the XR status address.
	reservedAddr = "203.0.113.7"

	// ephemeralNatIP is the ephemeral external IP the provider writes back on
	// the observed instance NIC when reservedIP is false. The no-reservation
	// case asserts the XR status address reads back from this value.
	ephemeralNatIP = "198.51.100.22"

	// saEmail is the service account email the observed service-account reports
	// at status.atProvider.email. Cases that supply it expect the instance and
	// the secret IAM member to render and the XR status to surface it.
	saEmail = "gateway@wgnet-test.iam.gserviceaccount.com"

	// secretAccessorRole is the IAM role granted to the gateway service account
	// on the WireGuard-key secret.
	secretAccessorRole = "roles/secretmanager.secretAccessor"

	// gatewaySecretID is spec.secretId for the fixtures. The template stamps it
	// onto the instance metadata as secret-id, which the gateway VM's keyfetch
	// reads to pull the WireGuard key from Secret Manager.
	gatewaySecretID = "gateway-wg"
)

// runFunction holds the gRPC client and the shipped template source, shared by
// every table case so the function container starts once.
type runFunction struct {
	client   fnv1.FunctionRunnerServiceClient
	template string
}

func TestXGatewayComposition(t *testing.T) {
	if os.Getenv("CYNO_INTEGRATION") == "" {
		t.Skip("set CYNO_INTEGRATION to run the composition integration test")
	}

	rf := newRunFunction(t)

	tests := []struct {
		name     string
		spec     map[string]any
		observed map[string]*fnv1.Resource
		assert   func(t *testing.T, resp *fnv1.RunFunctionResponse)
	}{
		{
			name: "reserved IP with mixed tcp/udp ports renders full stack",
			spec: map[string]any{
				"region":       testRegion,
				"zone":         testRegion + "-a",
				"machineType":  "e2-small",
				"image":        "projects/wgnet/global/images/gateway",
				"diskSizeGB":   30,
				"subnetCIDR":   "10.10.0.0/24",
				"reservedIP":   true,
				"userData":     "#cloud-config\n",
				"wgListenPort": 51820,
				"allowedPorts": []any{
					map[string]any{"port": 443, "protocol": "tcp"},
					map[string]any{"port": 80, "protocol": "tcp"},
					map[string]any{"port": 1194, "protocol": "udp"},
				},
				"serviceAccountId": "gateway",
				"secretId":         gatewaySecretID,
				"wgKeySecretRef": map[string]any{
					"name": "gateway-wg-key",
					"key":  "private",
				},
			},
			observed: map[string]*fnv1.Resource{
				"service-account": observedResource(t, "service-account", map[string]any{
					"apiVersion": "cloudplatform.gcp.m.upbound.io/v1beta1",
					"kind":       "ServiceAccount",
					"status":     map[string]any{"atProvider": map[string]any{"email": saEmail}},
				}),
				// Subnetwork and Firewall gate on a Ready network; supply it so
				// the full stack renders.
				"network": observedReady(t, "network", map[string]any{
					"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
					"kind":       "Network",
				}),
				"subnetwork": observedReady(t, "subnetwork", map[string]any{
					"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
					"kind":       "Subnetwork",
				}),
				"address": observedResource(t, "address", map[string]any{
					"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
					"kind":       "Address",
					"status":     map[string]any{"atProvider": map[string]any{"address": reservedAddr}},
				}),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()

				fw := desiredResource(t, resp, "firewall")
				if got := nestedString(t, fw, "spec", "forProvider", "direction"); got != "INGRESS" {
					t.Errorf("firewall direction = %q, want INGRESS", got)
				}
				allow := nestedSlice(t, fw, "spec", "forProvider", "allow")
				tcpPorts := allowPorts(t, allow, "tcp")
				assertSameSet(t, "firewall tcp ports", tcpPorts, []string{"443", "80"})
				udpPorts := allowPorts(t, allow, "udp")
				assertSameSet(t, "firewall udp ports", udpPorts, []string{"1194", "51820"})
				if !hasProtocol(allow, "icmp") {
					t.Errorf("firewall allow missing icmp rule, got %v", allow)
				}

				addr := desiredResource(t, resp, "address")
				if got := nestedString(t, addr, "spec", "forProvider", "addressType"); got != "EXTERNAL" {
					t.Errorf("address addressType = %q, want EXTERNAL", got)
				}

				secVer := desiredResource(t, resp, "secret-version")
				if got := nestedString(t, secVer, "spec", "forProvider", "secretDataSecretRef", "name"); got != "gateway-wg-key" {
					t.Errorf("secret-version secretDataSecretRef.name = %q, want gateway-wg-key", got)
				}
				if got := nestedString(t, secVer, "spec", "forProvider", "secretDataSecretRef", "key"); got != "private" {
					t.Errorf("secret-version secretDataSecretRef.key = %q, want private", got)
				}

				iam := desiredResource(t, resp, "secret-iam")
				if got := nestedString(t, iam, "spec", "forProvider", "member"); got != "serviceAccount:"+saEmail {
					t.Errorf("secret-iam member = %q, want serviceAccount:%s", got, saEmail)
				}
				if got := nestedString(t, iam, "spec", "forProvider", "role"); got != secretAccessorRole {
					t.Errorf("secret-iam role = %q, want %s", got, secretAccessorRole)
				}

				inst := desiredResource(t, resp, "instance")
				if got := nestedString(t, inst, "spec", "forProvider", "metadata", "user-data"); got != "#cloud-config\n" {
					t.Errorf("instance metadata user-data = %q, want cloud-config", got)
				}
				// The instance metadata carries secret-id sourced from
				// spec.secretId; the gateway VM's keyfetch reads it to pull the
				// WireGuard key from Secret Manager.
				if got := nestedString(t, inst, "spec", "forProvider", "metadata", "secret-id"); got != gatewaySecretID {
					t.Errorf("instance metadata secret-id = %q, want %q", got, gatewaySecretID)
				}
				if got := nestedString(t, inst, "spec", "forProvider", "metadata", "disable-legacy-endpoints"); got != "true" {
					t.Errorf("instance metadata disable-legacy-endpoints = %q, want true", got)
				}
				if got := nestedString(t, inst, "spec", "forProvider", "metadata", "block-project-ssh-keys"); got != "true" {
					t.Errorf("instance metadata block-project-ssh-keys = %q, want true", got)
				}
				if got := nestedString(t, inst, "spec", "forProvider", "serviceAccount", "email"); got != saEmail {
					t.Errorf("instance serviceAccount.email = %q, want %s", got, saEmail)
				}
				scopes := nestedSlice(t, inst, "spec", "forProvider", "serviceAccount", "scopes")
				assertSameSet(t, "instance serviceAccount.scopes", toStrings(t, scopes), []string{"https://www.googleapis.com/auth/cloud-platform"})

				natIP := nestedString(t, inst,
					"spec", "forProvider", "networkInterface", "0", "accessConfig", "0", "natIp")
				if natIP != reservedAddr {
					t.Errorf("instance natIp = %q, want reserved address %q", natIP, reservedAddr)
				}

				instRes := resp.GetDesired().GetResources()["instance"]
				if instRes.GetReady() == fnv1.Ready_READY_FALSE {
					t.Errorf("instance Ready = READY_FALSE, want not-false once SA email, subnet and address are known")
				}

				status := compositeStatus(t, resp)
				if got := digString(status, "address"); got != reservedAddr {
					t.Errorf("XR status.address = %q, want reserved address %q", got, reservedAddr)
				}
				if got := digString(status, "serviceAccountEmail"); got != saEmail {
					t.Errorf("XR status.serviceAccountEmail = %q, want %q", got, saEmail)
				}
			},
		},
		{
			name: "no reservation reads ephemeral natIp back from instance",
			spec: map[string]any{
				"region":           testRegion,
				"zone":             testRegion + "-a",
				"machineType":      "e2-small",
				"subnetCIDR":       "10.10.0.0/24",
				"reservedIP":       false,
				"wgListenPort":     51820,
				"serviceAccountId": "gateway",
				"secretId":         gatewaySecretID,
				"wgKeySecretRef": map[string]any{
					"name": "gateway-wg-key",
					"key":  "private",
				},
			},
			observed: map[string]*fnv1.Resource{
				"service-account": observedResource(t, "service-account", map[string]any{
					"apiVersion": "cloudplatform.gcp.m.upbound.io/v1beta1",
					"kind":       "ServiceAccount",
					"status":     map[string]any{"atProvider": map[string]any{"email": saEmail}},
				}),
				"subnetwork": observedReady(t, "subnetwork", map[string]any{
					"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
					"kind":       "Subnetwork",
				}),
				"instance": observedResource(t, "instance", map[string]any{
					"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
					"kind":       "Instance",
					"status": map[string]any{
						"atProvider": map[string]any{
							"networkInterface": []any{
								map[string]any{
									"accessConfig": []any{
										map[string]any{"natIp": ephemeralNatIP},
									},
								},
							},
						},
					},
				}),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				if _, ok := resp.GetDesired().GetResources()["address"]; ok {
					t.Errorf("address must not be desired when reservedIP is false")
				}

				inst := desiredResource(t, resp, "instance")
				nics := nestedSlice(t, inst, "spec", "forProvider", "networkInterface")
				if len(nics) == 0 {
					t.Fatalf("instance has no networkInterface")
				}
				nic0, ok := nics[0].(map[string]any)
				if !ok {
					t.Fatalf("networkInterface[0] is %T, want map", nics[0])
				}
				ac, ok := nic0["accessConfig"].([]any)
				if !ok || len(ac) == 0 {
					t.Fatalf("networkInterface[0].accessConfig is %T/%v, want non-empty slice", nic0["accessConfig"], nic0["accessConfig"])
				}
				ac0, ok := ac[0].(map[string]any)
				if !ok {
					t.Fatalf("accessConfig[0] is %T, want map", ac[0])
				}
				if _, ok := ac0["natIp"]; ok {
					t.Errorf("ephemeral accessConfig must not pin a natIp, got %v", ac0["natIp"])
				}

				status := compositeStatus(t, resp)
				if got := digString(status, "address"); got != ephemeralNatIP {
					t.Errorf("XR status.address = %q, want ephemeral natIp %q", got, ephemeralNatIP)
				}
			},
		},
		{
			name: "spot emits SPOT scheduling block",
			spec: map[string]any{
				"region":           testRegion,
				"zone":             testRegion + "-a",
				"machineType":      "e2-small",
				"subnetCIDR":       "10.10.0.0/24",
				"reservedIP":       false,
				"spot":             true,
				"wgListenPort":     51820,
				"serviceAccountId": "gateway",
				"secretId":         gatewaySecretID,
				"wgKeySecretRef": map[string]any{
					"name": "gateway-wg-key",
					"key":  "private",
				},
			},
			observed: map[string]*fnv1.Resource{
				"service-account": observedResource(t, "service-account", map[string]any{
					"apiVersion": "cloudplatform.gcp.m.upbound.io/v1beta1",
					"kind":       "ServiceAccount",
					"status":     map[string]any{"atProvider": map[string]any{"email": saEmail}},
				}),
				"subnetwork": observedReady(t, "subnetwork", map[string]any{
					"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
					"kind":       "Subnetwork",
				}),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				inst := desiredResource(t, resp, "instance")
				if got := nestedString(t, inst, "spec", "forProvider", "scheduling", "provisioningModel"); got != "SPOT" {
					t.Errorf("instance scheduling.provisioningModel = %q, want SPOT", got)
				}
				if got := nestedBool(t, inst, "spec", "forProvider", "scheduling", "preemptible"); !got {
					t.Errorf("instance scheduling.preemptible = false, want true under spot")
				}
			},
		},
		{
			name: "instance and iam withheld until SA email is observed",
			spec: map[string]any{
				"region":           testRegion,
				"zone":             testRegion + "-a",
				"machineType":      "e2-small",
				"subnetCIDR":       "10.10.0.0/24",
				"reservedIP":       false,
				"wgListenPort":     51820,
				"serviceAccountId": "gateway",
				"secretId":         gatewaySecretID,
				"wgKeySecretRef": map[string]any{
					"name": "gateway-wg-key",
					"key":  "private",
				},
			},
			observed: map[string]*fnv1.Resource{
				"subnetwork": observedReady(t, "subnetwork", map[string]any{
					"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
					"kind":       "Subnetwork",
				}),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				if _, ok := resp.GetDesired().GetResources()["network"]; !ok {
					t.Errorf("network must always be desired")
				}
				if _, ok := resp.GetDesired().GetResources()["service-account"]; !ok {
					t.Errorf("service-account must always be desired")
				}
				assertWithheld(t, resp, "instance")
				assertWithheld(t, resp, "secret-iam")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			req := rf.buildRequest(t, tt.spec, tt.observed)
			resp, err := rf.client.RunFunction(ctx, req)
			if err != nil {
				t.Fatalf("RunFunction: %v", err)
			}
			for _, res := range resp.GetResults() {
				if res.GetSeverity() == fnv1.Severity_SEVERITY_FATAL {
					t.Fatalf("function returned fatal result: %s", res.GetMessage())
				}
			}
			tt.assert(t, resp)
		})
	}
}

// newRunFunction starts the function container once, dials it over plaintext
// gRPC, and loads the shipped template. The container is terminated when t
// finishes.
func newRunFunction(t *testing.T) *runFunction {
	t.Helper()
	ctx := context.Background()

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        functionImage,
			Cmd:          []string{"--insecure"},
			ExposedPorts: []string{functionPort},
			Labels:       map[string]string{"cyno.test": "integration"},
			WaitingFor: wait.ForListeningPort(functionPort).
				WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start function container: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := ctr.MappedPort(ctx, functionPort)
	if err != nil {
		t.Fatalf("mapped port: %v", err)
	}

	conn, err := grpc.NewClient(host+":"+port.Port(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial function: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return &runFunction{
		client:   fnv1.NewFunctionRunnerServiceClient(conn),
		template: loadTemplate(t),
	}
}

// buildRequest assembles a RunFunctionRequest carrying the GoTemplate input,
// the XR built from spec, and any observed composed resources. The XR always
// uses xrName so the function's observed-resource keying lines up with the
// crossplane.io/composite label on observed fixtures.
func (rf *runFunction) buildRequest(t *testing.T, spec map[string]any, observed map[string]*fnv1.Resource) *fnv1.RunFunctionRequest {
	t.Helper()

	input, err := structpb.NewStruct(map[string]any{
		"apiVersion": "gotemplating.fn.crossplane.io/v1beta1",
		"kind":       "GoTemplate",
		"source":     "Inline",
		"inline": map[string]any{
			"template": rf.template,
		},
	})
	if err != nil {
		t.Fatalf("build input struct: %v", err)
	}

	xr := toStruct(t, map[string]any{
		"apiVersion": "infra.wgnet.dev/v1alpha1",
		"kind":       "XGateway",
		"metadata":   map[string]any{"name": xrName},
		"spec":       spec,
	})

	return &fnv1.RunFunctionRequest{
		Meta:  &fnv1.RequestMeta{Tag: xrName},
		Input: input,
		Observed: &fnv1.State{
			Composite: &fnv1.Resource{Resource: xr},
			Resources: observed,
		},
	}
}

// observedResource wraps a composed-resource body in the metadata
// function-go-templating uses to key .observed.resources: the
// crossplane.io/composition-resource-name annotation names the slot and the
// crossplane.io/composite label ties it to the XR.
func observedResource(t *testing.T, name string, body map[string]any) *fnv1.Resource {
	t.Helper()
	meta, ok := body["metadata"].(map[string]any)
	if !ok {
		meta = map[string]any{}
	}
	meta["annotations"] = map[string]any{
		"crossplane.io/composition-resource-name": name,
	}
	meta["labels"] = map[string]any{
		"crossplane.io/composite": xrName,
	}
	body["metadata"] = meta
	return &fnv1.Resource{Resource: toStruct(t, body)}
}

// observedReady is observedResource with a Ready=True condition stamped on the
// observed body, modelling a composed resource the provider has reconciled.
func observedReady(t *testing.T, name string, body map[string]any) *fnv1.Resource {
	t.Helper()
	status, ok := body["status"].(map[string]any)
	if !ok {
		status = map[string]any{}
	}
	status["conditions"] = []any{
		map[string]any{"type": "Ready", "status": "True"},
	}
	body["status"] = status
	return observedResource(t, name, body)
}

// loadTemplate reads the shipped composition template relative to this test
// file so the test always validates the bytes the chart ships.
func loadTemplate(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	path := filepath.Join(repoRoot, "k8s", "charts", "wireguard-gateway-operator", "crossplane", "gcp", "composition.gotmpl")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read template %s: %v", path, err)
	}
	return string(b)
}

func toStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("build struct: %v", err)
	}
	return s
}

// desiredResource returns the body of the named desired composed resource,
// failing the test if it is absent.
func desiredResource(t *testing.T, resp *fnv1.RunFunctionResponse, name string) map[string]any {
	t.Helper()
	res, ok := resp.GetDesired().GetResources()[name]
	if !ok {
		t.Fatalf("desired resource %q absent; got keys %v", name, desiredKeys(resp))
	}
	return res.GetResource().AsMap()
}

// assertWithheld fails unless the named resource is either absent from desired
// or present but marked Ready=READY_FALSE. Both encode "not yet actionable" in
// the function-go-templating + auto-ready contract.
func assertWithheld(t *testing.T, resp *fnv1.RunFunctionResponse, name string) {
	t.Helper()
	res, ok := resp.GetDesired().GetResources()[name]
	if !ok {
		return
	}
	if res.GetReady() != fnv1.Ready_READY_FALSE {
		t.Errorf("resource %q is desired with Ready=%v, want absent or READY_FALSE", name, res.GetReady())
	}
}

// compositeStatus returns the status map the function set on the desired XR.
func compositeStatus(t *testing.T, resp *fnv1.RunFunctionResponse) map[string]any {
	t.Helper()
	comp := resp.GetDesired().GetComposite()
	if comp == nil || comp.GetResource() == nil {
		t.Fatal("desired composite resource absent")
	}
	status, ok := comp.GetResource().AsMap()["status"].(map[string]any)
	if !ok {
		t.Fatalf("desired composite has no status map; got %v", comp.GetResource().AsMap())
	}
	return status
}

func desiredKeys(resp *fnv1.RunFunctionResponse) []string {
	keys := make([]string, 0, len(resp.GetDesired().GetResources()))
	for k := range resp.GetDesired().GetResources() {
		keys = append(keys, k)
	}
	return keys
}

// allowPorts returns the ports of the firewall allow rule for the given
// protocol, or nil if no rule matches.
func allowPorts(t *testing.T, allow []any, protocol string) []string {
	t.Helper()
	for _, raw := range allow {
		rule, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("allow rule is %T, want map", raw)
		}
		if rule["protocol"] != protocol {
			continue
		}
		portsRaw, ok := rule["ports"].([]any)
		if !ok {
			return nil
		}
		return toStrings(t, portsRaw)
	}
	return nil
}

// hasProtocol reports whether the allow list carries a rule for the protocol.
func hasProtocol(allow []any, protocol string) bool {
	for _, raw := range allow {
		rule, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if rule["protocol"] == protocol {
			return true
		}
	}
	return false
}

// toStrings asserts every element is a string and returns them.
func toStrings(t *testing.T, in []any) []string {
	t.Helper()
	out := make([]string, 0, len(in))
	for _, v := range in {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("element %v is %T, want string", v, v)
		}
		out = append(out, s)
	}
	return out
}

// assertSameSet fails unless got and want contain the same elements ignoring
// order, which suits firewall ports and scopes whose ordering is not contractual.
func assertSameSet(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s = %v, want same set as %v", label, got, want)
		return
	}
	counts := map[string]int{}
	for _, v := range want {
		counts[v]++
	}
	for _, v := range got {
		counts[v]--
	}
	for v, c := range counts {
		if c != 0 {
			t.Errorf("%s = %v, want same set as %v (mismatch on %q)", label, got, want, v)
			return
		}
	}
}

// nestedString walks the map by path and returns the string at the leaf,
// failing the test if any segment is missing or not the expected type. Numeric
// path segments index into slices.
func nestedString(t *testing.T, m map[string]any, path ...string) string {
	t.Helper()
	v := nested(t, m, path...)
	s, ok := v.(string)
	if !ok {
		t.Fatalf("value at %v is %T, want string", path, v)
	}
	return s
}

func nestedBool(t *testing.T, m map[string]any, path ...string) bool {
	t.Helper()
	v := nested(t, m, path...)
	b, ok := v.(bool)
	if !ok {
		t.Fatalf("value at %v is %T, want bool", path, v)
	}
	return b
}

func nestedSlice(t *testing.T, m map[string]any, path ...string) []any {
	t.Helper()
	v := nested(t, m, path...)
	s, ok := v.([]any)
	if !ok {
		t.Fatalf("value at %v is %T, want slice", path, v)
	}
	return s
}

// nested walks m by path. A numeric segment indexes the current value as a
// slice; any other segment keys it as a map.
func nested(t *testing.T, m map[string]any, path ...string) any {
	t.Helper()
	var cur any = m
	for i, key := range path {
		if idx, isIdx := sliceIndex(key); isIdx {
			asSlice, ok := cur.([]any)
			if !ok {
				t.Fatalf("path %v: segment %q parent is %T, want slice", path, key, cur)
			}
			if idx < 0 || idx >= len(asSlice) {
				t.Fatalf("path %v: index %d out of range (len %d)", path, idx, len(asSlice))
			}
			cur = asSlice[idx]
			continue
		}
		asMap, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("path %v: segment %q parent is %T, want map", path, key, cur)
		}
		cur, ok = asMap[key]
		if !ok {
			t.Fatalf("path %v: segment %q (index %d) missing", path, key, i)
		}
	}
	return cur
}

// sliceIndex parses a path segment as a non-negative slice index.
func sliceIndex(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

// digString returns m[key] as a string, or "" when absent or not a string.
// Mirrors the template's tolerance for optional status fields.
func digString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}
