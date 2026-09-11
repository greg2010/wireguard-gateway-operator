// Package crossplane exercises the shipped GCP XGatewayGCP composition template by
// driving the real function-go-templating image's FunctionRunnerService over gRPC,
// the same contract Crossplane invokes per reconcile.
package crossplane

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	fnv1 "github.com/crossplane/function-sdk-go/proto/v1"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
	"sigs.k8s.io/yaml"
)

const (
	// functionPort is the plaintext gRPC port function-go-templating listens on
	// when started with --insecure.
	functionPort = "9443/tcp"

	// xrName is the composite resource name every case uses; the function keys observed
	// resources by it via the crossplane.io/composite label, so fixtures must carry it too.
	xrName = "xgateway-smoke"

	// testRegion is the region every fixture XR requests.
	testRegion = "us-central1"

	// reservedAddr is the external IP the observed Address reports; the reservedIP
	// case asserts it surfaces on the instance accessConfig natIp and the XR status.
	reservedAddr = "203.0.113.7"

	// ephemeralNatIP is the external IP the provider writes back on the observed NIC
	// when reservedIP is false; the no-reservation case reads the XR status from it.
	ephemeralNatIP = "198.51.100.22"

	// saEmail is the service-account email the observed service-account reports at
	// status.atProvider.email, gating the instance, secret IAM member, and XR status.
	saEmail = "gateway@wgnet-test.iam.gserviceaccount.com"

	// secretAccessorRole is the IAM role granted to the gateway service account
	// on the WireGuard-key secret.
	secretAccessorRole = "roles/secretmanager.secretAccessor"

	// gatewaySecretID is spec.secretId; the template stamps it onto the instance
	// metadata as secret-id, which the VM's keyfetch reads to pull the WireGuard key.
	gatewaySecretID = "gateway-wg"

	// testProjectID is spec.projectID; the template stamps it onto the instance
	// metadata as project-id, which the VM's keyfetch reads to build the SM URL.
	testProjectID = "wgnet-test-project"

	// sharedNetworkName is spec.sharedNetworkName, the VPC the shared-network
	// composition creates; the template stamps it onto the Firewall and instance NIC.
	sharedNetworkName = "wgnet-test"

	// providerConfigName is spec.providerConfigName, the Crossplane ClusterProviderConfig
	// the template stamps onto every composed resource's providerConfigRef.name.
	providerConfigName = "test-provider-config"

	// iapSourceRange is GCP's fixed source range for IAP TCP forwarding; the
	// firewall-iap resource must allow SSH from exactly this range.
	iapSourceRange = "35.235.240.0/20"
)

// runFunction holds the gRPC client to the shared function container, which every
// test renders its own composition template against.
type runFunction struct {
	client fnv1.FunctionRunnerServiceClient
}

func TestXGatewayGCPComposition(t *testing.T) {
	if os.Getenv("GATEWAY_INTEGRATION") == "" {
		t.Skip("set GATEWAY_INTEGRATION to run the composition integration test")
	}

	rf := newRunFunction(t)
	template := loadTemplate(t)

	tests := []struct {
		name     string
		spec     map[string]any
		observed map[string]*fnv1.Resource
		assert   func(t *testing.T, resp *fnv1.RunFunctionResponse)
	}{
		{
			name: "reserved IP with mixed tcp/udp ports renders full stack",
			spec: map[string]any{
				"region":             testRegion,
				"zone":               testRegion + "-a",
				"machineType":        "e2-small",
				"image":              "projects/wgnet/global/images/gateway",
				"diskSizeGB":         30,
				"sharedNetworkName":  sharedNetworkName,
				"providerConfigName": providerConfigName,
				"reservedIP":         true,
				"userData":           "#cloud-config\n",
				"wgListenPort":       51820,
				"wgMTU":              1380,
				"wgGatewayAddress":   "10.99.0.1",
				"wgLinkAddress":      "10.99.0.2",
				"wgSubnet":           "10.99.0.0/29",
				"projectID":          testProjectID,
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
				if got := nestedString(t, fw, "spec", "forProvider", "network"); got != sharedNetworkName {
					t.Errorf("firewall network = %q, want shared network %q", got, sharedNetworkName)
				}
				if got := nestedString(t, fw, "spec", "providerConfigRef", "name"); got != providerConfigName {
					t.Errorf("firewall providerConfigRef.name = %q, want %q", got, providerConfigName)
				}
				targetSAs := nestedSlice(t, fw, "spec", "forProvider", "targetServiceAccounts")
				assertSameSet(t, "firewall targetServiceAccounts", toStrings(t, targetSAs), []string{saEmail})
				allow := nestedSlice(t, fw, "spec", "forProvider", "allow")
				tcpPorts := allowPorts(t, allow, "tcp")
				assertSameSet(t, "firewall tcp ports", tcpPorts, []string{"443", "80"})
				udpPorts := allowPorts(t, allow, "udp")
				assertSameSet(t, "firewall udp ports", udpPorts, []string{"1194", "51820"})
				if hasProtocol(allow, "icmp") {
					t.Errorf("firewall allow must not open icmp to the internet, got %v", allow)
				}

				// enableOsLogin is omitted from this spec, so the template's dig
				// default governs and the IAP SSH firewall rule must be desired.
				fwIAP := desiredResource(t, resp, "firewall-iap")
				if got := nestedString(t, fwIAP, "spec", "forProvider", "network"); got != sharedNetworkName {
					t.Errorf("firewall-iap network = %q, want shared network %q", got, sharedNetworkName)
				}
				if got := nestedString(t, fwIAP, "spec", "providerConfigRef", "name"); got != providerConfigName {
					t.Errorf("firewall-iap providerConfigRef.name = %q, want %q", got, providerConfigName)
				}
				iapSourceRanges := nestedSlice(t, fwIAP, "spec", "forProvider", "sourceRanges")
				assertSameSet(t, "firewall-iap sourceRanges", toStrings(t, iapSourceRanges), []string{iapSourceRange})
				iapTargetSAs := nestedSlice(t, fwIAP, "spec", "forProvider", "targetServiceAccounts")
				assertSameSet(t, "firewall-iap targetServiceAccounts", toStrings(t, iapTargetSAs), []string{saEmail})
				iapAllow := nestedSlice(t, fwIAP, "spec", "forProvider", "allow")
				assertSameSet(t, "firewall-iap tcp ports", allowPorts(t, iapAllow, "tcp"), []string{"22"})

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
				// The instance metadata carries secret-id from spec.secretId; the VM's
				// keyfetch reads it to pull the WireGuard key from Secret Manager.
				if got := nestedString(t, inst, "spec", "forProvider", "metadata", "secret-id"); got != gatewaySecretID {
					t.Errorf("instance metadata secret-id = %q, want %q", got, gatewaySecretID)
				}
				// The VM's keyfetch reads these per-Gateway values off the instance
				// metadata to render the netdev, nftables, wg0 address and SM URL.
				wantMeta := map[string]string{
					"wg-listen-port":     "51820",
					"wg-mtu":             "1380",
					"wg-gateway-address": "10.99.0.1",
					"wg-link-address":    "10.99.0.2",
					"wg-subnet":          "10.99.0.0/29",
					"project-id":         testProjectID,
					"traffic-policy":     "cluster",
				}
				for key, want := range wantMeta {
					if got := nestedString(t, inst, "spec", "forProvider", "metadata", key); got != want {
						t.Errorf("instance metadata %s = %q, want %q", key, got, want)
					}
				}
				if got := nestedString(t, inst, "spec", "forProvider", "metadata", "disable-legacy-endpoints"); got != "true" {
					t.Errorf("instance metadata disable-legacy-endpoints = %q, want true", got)
				}
				if got := nestedString(t, inst, "spec", "forProvider", "metadata", "block-project-ssh-keys"); got != "true" {
					t.Errorf("instance metadata block-project-ssh-keys = %q, want true", got)
				}
				// enableOsLogin is omitted from this spec, so the template's dig default
				// governs and OS Login is on.
				if got := nestedString(t, inst, "spec", "forProvider", "metadata", "enable-oslogin"); got != "TRUE" {
					t.Errorf("instance metadata enable-oslogin = %q, want TRUE (dig default)", got)
				}
				if got := nestedString(t, inst, "spec", "forProvider", "serviceAccount", "email"); got != saEmail {
					t.Errorf("instance serviceAccount.email = %q, want %s", got, saEmail)
				}
				scopes := nestedSlice(t, inst, "spec", "forProvider", "serviceAccount", "scopes")
				assertSameSet(t, "instance serviceAccount.scopes", toStrings(t, scopes), []string{"https://www.googleapis.com/auth/cloud-platform"})

				assertSharedNetworkNIC(t, inst)

				if got := nestedString(t, inst, "spec", "providerConfigRef", "name"); got != providerConfigName {
					t.Errorf("instance providerConfigRef.name = %q, want %q", got, providerConfigName)
				}

				natIP := nestedString(t, inst,
					"spec", "forProvider", "networkInterface", "0", "accessConfig", "0", "natIp")
				if natIP != reservedAddr {
					t.Errorf("instance natIp = %q, want reserved address %q", natIP, reservedAddr)
				}

				instRes := resp.GetDesired().GetResources()["instance"]
				if instRes.GetReady() == fnv1.Ready_READY_FALSE {
					t.Errorf("instance Ready = READY_FALSE, want not-false once SA email and address are known")
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
			// providerConfigName is omitted from this spec, pinning the template's
			// dig fallback to the "default" ClusterProviderConfig.
			name: "no reservation reads ephemeral natIp back from instance",
			spec: map[string]any{
				"region":            testRegion,
				"zone":              testRegion + "-a",
				"machineType":       "e2-small",
				"sharedNetworkName": sharedNetworkName,
				"reservedIP":        false,
				"wgListenPort":      51820,
				"serviceAccountId":  "gateway",
				"secretId":          gatewaySecretID,
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
				assertSharedNetworkNIC(t, inst)
				if got := nestedString(t, inst, "spec", "forProvider", "desiredStatus"); got != "RUNNING" {
					t.Errorf("instance desiredStatus = %q, want RUNNING", got)
				}
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
				if got := nestedString(t, inst, "spec", "providerConfigRef", "name"); got != "default" {
					t.Errorf("instance providerConfigRef.name = %q, want default (providerConfigName omitted from spec)", got)
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
				"region":             testRegion,
				"zone":               testRegion + "-a",
				"machineType":        "e2-small",
				"sharedNetworkName":  sharedNetworkName,
				"providerConfigName": providerConfigName,
				"reservedIP":         false,
				"spot":               true,
				"enableOsLogin":      false,
				"wgListenPort":       51820,
				"serviceAccountId":   "gateway",
				"secretId":           gatewaySecretID,
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
				if got := nestedString(t, inst, "spec", "forProvider", "scheduling", "onHostMaintenance"); got != "TERMINATE" {
					t.Errorf("instance scheduling.onHostMaintenance = %q, want TERMINATE", got)
				}
				if nestedBool(t, inst, "spec", "forProvider", "scheduling", "automaticRestart") {
					t.Errorf("instance scheduling.automaticRestart = true, want false under spot")
				}
				if got := nestedString(t, inst, "spec", "forProvider", "desiredStatus"); got != "RUNNING" {
					t.Errorf("instance desiredStatus = %q, want RUNNING", got)
				}
				// enableOsLogin is false on this spec, so OS Login is explicitly disabled.
				if got := nestedString(t, inst, "spec", "forProvider", "metadata", "enable-oslogin"); got != "FALSE" {
					t.Errorf("instance metadata enable-oslogin = %q, want FALSE (enableOsLogin=false)", got)
				}
				// OS Login is disabled on this spec, so IAP SSH has no way in and the
				// IAP firewall rule must not be desired.
				if _, ok := resp.GetDesired().GetResources()["firewall-iap"]; ok {
					t.Errorf("firewall-iap must not be desired when enableOsLogin is false")
				}
			},
		},
		{
			name: "instance and iam withheld until SA email is observed",
			spec: map[string]any{
				"region":             testRegion,
				"zone":               testRegion + "-a",
				"machineType":        "e2-small",
				"sharedNetworkName":  sharedNetworkName,
				"providerConfigName": providerConfigName,
				"reservedIP":         false,
				"wgListenPort":       51820,
				"serviceAccountId":   "gateway",
				"secretId":           gatewaySecretID,
				"wgKeySecretRef": map[string]any{
					"name": "gateway-wg-key",
					"key":  "private",
				},
			},
			observed: map[string]*fnv1.Resource{},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				if _, ok := resp.GetDesired().GetResources()["service-account"]; !ok {
					t.Errorf("service-account must always be desired")
				}
				assertWithheld(t, resp, "firewall")
				assertWithheld(t, resp, "instance")
				assertWithheld(t, resp, "secret-iam")
			},
		},
		{
			// A non-default wgListenPort and projectID must flow verbatim onto the instance
			// metadata, so keyfetch reads the per-Gateway value, not a chart-baked one.
			name: "non-default wgListenPort and projectID reach instance metadata",
			spec: map[string]any{
				"region":             testRegion,
				"zone":               testRegion + "-a",
				"machineType":        "e2-small",
				"sharedNetworkName":  sharedNetworkName,
				"providerConfigName": providerConfigName,
				"reservedIP":         false,
				"wgListenPort":       51999,
				"wgMTU":              1280,
				"wgGatewayAddress":   "10.50.0.1",
				"wgLinkAddress":      "10.50.0.2",
				"wgSubnet":           "10.50.0.0/29",
				"projectID":          "other-project",
				"serviceAccountId":   "gateway",
				"secretId":           gatewaySecretID,
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
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				inst := desiredResource(t, resp, "instance")
				wantMeta := map[string]string{
					"wg-listen-port":     "51999",
					"wg-mtu":             "1280",
					"wg-gateway-address": "10.50.0.1",
					"wg-link-address":    "10.50.0.2",
					"wg-subnet":          "10.50.0.0/29",
					"project-id":         "other-project",
				}
				for key, want := range wantMeta {
					if got := nestedString(t, inst, "spec", "forProvider", "metadata", key); got != want {
						t.Errorf("instance metadata %s = %q, want %q", key, got, want)
					}
				}
				assertSharedNetworkNIC(t, inst)

				// The non-default listen port must also open at the GCP firewall so the
				// WireGuard underlay is reachable on the port the VM listens on.
				fw := desiredResource(t, resp, "firewall")
				if got := nestedString(t, fw, "spec", "forProvider", "network"); got != sharedNetworkName {
					t.Errorf("firewall network = %q, want shared network %q", got, sharedNetworkName)
				}
				targetSAs := nestedSlice(t, fw, "spec", "forProvider", "targetServiceAccounts")
				assertSameSet(t, "firewall targetServiceAccounts", toStrings(t, targetSAs), []string{saEmail})
				allow := nestedSlice(t, fw, "spec", "forProvider", "allow")
				udpPorts := allowPorts(t, allow, "udp")
				assertSameSet(t, "firewall udp ports", udpPorts, []string{"51999"})
			},
		},
		{
			// keyfetch.sh turns traffic-policy=local into the postrouting return verdict, so
			// the VM stops masquerading tunnel egress and the client source survives.
			name: "trafficPolicy local reaches instance metadata",
			spec: map[string]any{
				"region":             testRegion,
				"zone":               testRegion + "-a",
				"machineType":        "e2-small",
				"sharedNetworkName":  sharedNetworkName,
				"providerConfigName": providerConfigName,
				"reservedIP":         false,
				"wgListenPort":       51820,
				"wgMTU":              1380,
				"wgGatewayAddress":   "10.99.0.1",
				"wgLinkAddress":      "10.99.0.2",
				"wgSubnet":           "10.99.0.0/29",
				"projectID":          testProjectID,
				"trafficPolicy":      "local",
				"serviceAccountId":   "gateway",
				"secretId":           gatewaySecretID,
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
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				inst := desiredResource(t, resp, "instance")
				if got := nestedString(t, inst, "spec", "forProvider", "metadata", "traffic-policy"); got != "local" {
					t.Errorf("instance metadata traffic-policy = %q, want local", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			req := rf.buildRequestFor(t, template, "XGatewayGCP", tt.spec, tt.observed)
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

func TestXGatewayNetworkComposition(t *testing.T) {
	if os.Getenv("GATEWAY_INTEGRATION") == "" {
		t.Skip("set GATEWAY_INTEGRATION to run the composition integration test")
	}

	rf := newRunFunction(t)
	template := loadNetworkTemplate(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := rf.buildRequestFor(t, template, "XGatewayNetwork", map[string]any{
		"name":               sharedNetworkName,
		"providerConfigName": providerConfigName,
	}, nil)
	resp, err := rf.client.RunFunction(ctx, req)
	if err != nil {
		t.Fatalf("RunFunction: %v", err)
	}
	for _, res := range resp.GetResults() {
		if res.GetSeverity() == fnv1.Severity_SEVERITY_FATAL {
			t.Fatalf("function returned fatal result: %s", res.GetMessage())
		}
	}

	if got := desiredKeys(resp); len(got) != 1 || got[0] != "network" {
		t.Fatalf("desired resources = %v, want exactly [network]", got)
	}

	network := desiredResource(t, resp, "network")
	if got := nestedString(t, network, "kind"); got != "Network" {
		t.Errorf("desired resource kind = %q, want Network", got)
	}
	if got := nestedString(t, network, "metadata", "annotations", "crossplane.io/external-name"); got != sharedNetworkName {
		t.Errorf("network external-name = %q, want %q", got, sharedNetworkName)
	}
	if got := nestedString(t, network, "spec", "providerConfigRef", "name"); got != providerConfigName {
		t.Errorf("network providerConfigRef.name = %q, want %q", got, providerConfigName)
	}
	if got := nestedBool(t, network, "spec", "forProvider", "autoCreateSubnetworks"); !got {
		t.Errorf("network autoCreateSubnetworks = false, want true")
	}
}

// TestMain terminates the function container after the last test. Its lifetime
// spans both composition tests, so no single test's cleanup can own it.
func TestMain(m *testing.M) {
	code := m.Run()
	if functionStop != nil {
		if err := functionStop(); err != nil {
			log.Printf("stop function container: %v", err)
		}
	}
	os.Exit(code)
}

var (
	functionOnce sync.Once
	functionConn *grpc.ClientConn
	functionStop func() error
	functionErr  error
)

// newRunFunction returns a client for the function container, starting it on
// first use. Both composition tests render against the one container.
func newRunFunction(t *testing.T) *runFunction {
	t.Helper()

	// Resolved outside the once so the failure is reported against whichever test
	// asks, rather than only the first.
	image := goTemplatingImage(t)
	functionOnce.Do(func() {
		functionConn, functionStop, functionErr = startFunction(image)
	})
	if functionErr != nil {
		t.Fatalf("start function: %v", functionErr)
	}

	return &runFunction{client: fnv1.NewFunctionRunnerServiceClient(functionConn)}
}

// startFunction boots the function image and returns a connection that has
// reached READY, plus a terminator that is safe to call whatever the error.
func startFunction(image string) (*grpc.ClientConn, func() error, error) {
	ctx := context.Background()

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        image,
			Cmd:          []string{"--insecure"},
			ExposedPorts: []string{functionPort},
			Labels:       map[string]string{"gateway.test": "integration"},
			WaitingFor: wait.ForListeningPort(functionPort).
				WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	// Built before the error check: a start that fails its wait strategy still
	// returns a live container, which would otherwise leak for the runtime's lifetime.
	stop := func() error { return nil }
	if ctr != nil {
		stop = func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			return ctr.Terminate(ctx)
		}
	}
	if err != nil {
		return nil, stop, err
	}

	host, err := ctr.Host(ctx)
	if err != nil {
		return nil, stop, fmt.Errorf("container host: %w", err)
	}
	port, err := ctr.MappedPort(ctx, functionPort)
	if err != nil {
		return nil, stop, fmt.Errorf("mapped port: %w", err)
	}

	conn, err := grpc.NewClient(host+":"+port.Port(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, stop, fmt.Errorf("dial function: %w", err)
	}
	terminate := stop
	stop = func() error { return errors.Join(conn.Close(), terminate()) }

	if err := waitForReady(conn); err != nil {
		return nil, stop, err
	}
	return conn, stop, nil
}

// waitForReady blocks on the HTTP/2 handshake: the image is distroless, so the wait
// strategy probes only the mapped port and the first RPC would race the server's listen.
func waitForReady(conn *grpc.ClientConn) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			return nil
		}
		conn.Connect()
		if !conn.WaitForStateChange(ctx, state) {
			return fmt.Errorf("function container never became gRPC-ready: last state %s", state)
		}
	}
}

// buildRequestFor names the XR xrName so the function's observed-resource keying lines up.
// The template and kind are arguments, so one container renders either composition.
func (rf *runFunction) buildRequestFor(t *testing.T, template, kind string, spec map[string]any, observed map[string]*fnv1.Resource) *fnv1.RunFunctionRequest {
	t.Helper()

	input, err := structpb.NewStruct(map[string]any{
		"apiVersion": "gotemplating.fn.crossplane.io/v1beta1",
		"kind":       "GoTemplate",
		"source":     "Inline",
		"inline": map[string]any{
			"template": template,
		},
	})
	if err != nil {
		t.Fatalf("build input struct: %v", err)
	}

	xr := toStruct(t, map[string]any{
		"apiVersion": "infra.wgnet.dev/v1alpha1",
		"kind":       kind,
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

// observedResource adds the metadata function-go-templating keys .observed.resources by:
// the composition-resource-name annotation names the slot, the composite label ties the XR.
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

// loadTemplate reads the shipped per-gateway composition template relative to
// this test file so the test always validates the bytes the chart ships.
func loadTemplate(t *testing.T) string {
	t.Helper()
	return readChartFile(t, filepath.Join("crossplane", "gcp", "composition.gotmpl"))
}

// loadNetworkTemplate reads the shipped shared-network composition, the separate template
// that owns the VPC each per-gateway instance and firewall is wired onto.
func loadNetworkTemplate(t *testing.T) string {
	t.Helper()
	return readChartFile(t, filepath.Join("crossplane", "gcp", "network-composition.gotmpl"))
}

// goTemplatingImage reads the digest out of the providers chart values, the single source
// of truth for the function image the test boots.
func goTemplatingImage(t *testing.T) string {
	t.Helper()
	path := filepath.Join(repoRoot(t),
		"k8s", "infra", "crossplane", "crossplane-providers", "values.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read providers values %s: %v", path, err)
	}

	var values struct {
		Functions struct {
			GoTemplating struct {
				Package string `json:"package"`
			} `json:"goTemplating"`
		} `json:"functions"`
	}
	if err := yaml.Unmarshal(b, &values); err != nil {
		t.Fatalf("parse providers values %s: %v", path, err)
	}

	pkg := values.Functions.GoTemplating.Package
	if pkg == "" {
		t.Fatalf("functions.goTemplating.package empty in %s", path)
	}
	return pkg
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

// assertWithheld fails unless the named resource is absent from desired or marked
// Ready=READY_FALSE: both encode "not yet actionable" under the auto-ready contract.
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

// assertSharedNetworkNIC asserts the instance's primary NIC attaches directly to
// the shared VPC by name and carries no subnetwork wiring.
func assertSharedNetworkNIC(t *testing.T, inst map[string]any) {
	t.Helper()
	nics := nestedSlice(t, inst, "spec", "forProvider", "networkInterface")
	if len(nics) == 0 {
		t.Fatalf("instance has no networkInterface")
	}
	nic0, ok := nics[0].(map[string]any)
	if !ok {
		t.Fatalf("networkInterface[0] is %T, want map", nics[0])
	}
	if got, _ := nic0["network"].(string); got != sharedNetworkName {
		t.Errorf("instance networkInterface[0].network = %q, want shared network %q", got, sharedNetworkName)
	}
	if _, ok := nic0["subnetwork"]; ok {
		t.Errorf("instance networkInterface[0] must not pin a subnetwork, got %v", nic0["subnetwork"])
	}
	if _, ok := nic0["subnetworkSelector"]; ok {
		t.Errorf("instance networkInterface[0] must not pin a subnetworkSelector, got %v", nic0["subnetworkSelector"])
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

// nestedString returns the string at the leaf of path, failing the test on a missing or
// mistyped segment. A numeric segment indexes a slice.
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
