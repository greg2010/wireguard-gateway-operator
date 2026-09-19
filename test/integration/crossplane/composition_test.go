// Package crossplane exercises the shipped GCP XGatewayGCP composition template by
// driving the real function-go-templating image's FunctionRunnerService over gRPC,
// the same contract Crossplane invokes per reconcile.
package crossplane

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
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

	// reservedAddr is the external IP the observed Address reports; the Reserved and
	// External cases assert it surfaces on the instance accessConfig natIp and the XR status.
	reservedAddr = "203.0.113.7"

	// ephemeralNatIP is the external IP the provider writes back on the observed NIC
	// under type Ephemeral; the ephemeral cases read the XR status from it.
	ephemeralNatIP = "198.51.100.22"

	// externalAddrName is the name of a pre-existing GCP address the External + name
	// form adopts through an observe-only composed Address.
	externalAddrName = "prod-edge-ip"

	// priorNatIP is the address an already-running instance reports back while the
	// target address is still unknown; the VM must keep it rather than lose its IP.
	priorNatIP = "203.0.113.99"

	// targetNatIP is the address the composed Address reports once it is allocated.
	targetNatIP = "203.0.113.100"

	// priorSAEmail is the service-account email an already-running instance reports at
	// status.atProvider, which it must keep while the composed service account is silent.
	priorSAEmail = "prior@wgnet-test.iam.gserviceaccount.com"

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

	// lbTemplateRevision is the templateRevision every load-balanced fixture uses
	// unless a case overrides it to exercise the revision-change behaviour itself.
	lbTemplateRevision = "rev00001"

	// migHealthCheckSelfLink is the selfLink an observed "health-check-mig" reports,
	// which the mig's autoHealingPolicies.healthCheck is built from verbatim.
	migHealthCheckSelfLink = "https://compute.googleapis.com/compute/v1/projects/wgnet-test/regions/us-central1/healthChecks/gw-health-check-mig"
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
		// wantRenderErr, when set, expects the render to fail with an error containing it.
		wantRenderErr string
	}{
		{
			name: "reserved with mixed tcp/udp ports renders full stack",
			spec: map[string]any{
				"region":             testRegion,
				"zone":               testRegion + "-a",
				"machineType":        "e2-small",
				"image":              "projects/wgnet/global/images/gateway",
				"diskSizeGB":         30,
				"sharedNetworkName":  sharedNetworkName,
				"providerConfigName": providerConfigName,
				"address":            map[string]any{"type": "Reserved"},
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
				"members": []any{map[string]any{
					"name": "gateway-instance", "slot": 0, "tunnelAddress": "10.99.0.2/29",
					"kubernetesSecretName": "gateway-wg-key", "cloudSecretName": "secret",
					"cloudSecretVersionName": "secret-version", "cloudSecretIamMemberName": "secret-iam",
				}},
			},
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
				"address":         observedAddress(t, "address", reservedAddr),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()

				assertExactDesiredNames(t, resp, []string{
					"address", "firewall", "firewall-iap", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})

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
				assertSameSet(t, "firewall protocols", allowProtocols(t, allow), []string{"tcp", "udp"})

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
				assertAddressForProvider(t, addr, map[string]any{
					"addressType": "EXTERNAL",
					"region":      testRegion,
				})

				secVer := desiredResource(t, resp, "secret-version")
				if got := nestedString(t, secVer, "spec", "forProvider", "secretDataSecretRef", "name"); got != "gateway-wg-key" {
					t.Errorf("secret-version secretDataSecretRef.name = %q, want gateway-wg-key", got)
				}
				if got := nestedString(t, secVer, "spec", "forProvider", "secretDataSecretRef", "key"); got != "bundle" {
					t.Errorf("secret-version secretDataSecretRef.key = %q, want bundle", got)
				}

				iam := desiredResource(t, resp, "secret-iam")
				if got := nestedString(t, iam, "spec", "forProvider", "member"); got != "serviceAccount:"+saEmail {
					t.Errorf("secret-iam member = %q, want serviceAccount:%s", got, saEmail)
				}
				if got := nestedString(t, iam, "spec", "forProvider", "role"); got != secretAccessorRole {
					t.Errorf("secret-iam role = %q, want %s", got, secretAccessorRole)
				}

				inst := desiredResource(t, resp, "instance")
				// keyfetch reads these per-Gateway metadata values to render netdev, nftables, wg0 and SM URL.
				// enableOsLogin is omitted so the template's dig default leaves OS Login on.
				wantMeta := map[string]string{
					"wg-listen-port":           "51820",
					"wg-mtu":                   "1380",
					"wg-link-address":          "10.99.0.2",
					"project-id":               testProjectID,
					"traffic-policy":           "cluster",
					"disable-legacy-endpoints": "true",
					"block-project-ssh-keys":   "true",
					"enable-oslogin":           "TRUE",
					"user-data":                "#cloud-config\n",
					"secret-id":                gatewaySecretID,
				}
				for key, want := range wantMeta {
					if got := nestedString(t, inst, "spec", "forProvider", "metadata", key); got != want {
						t.Errorf("instance metadata %s = %q, want %q", key, got, want)
					}
				}
				metadata := nestedMap(t, inst, "spec", "forProvider", "metadata")
				gotKeys := make([]string, 0, len(metadata))
				for k := range metadata {
					gotKeys = append(gotKeys, k)
				}
				wantKeys := make([]string, 0, len(wantMeta))
				for k := range wantMeta {
					wantKeys = append(wantKeys, k)
				}
				assertSameSet(t, "instance metadata keys", gotKeys, wantKeys)
				if got := nestedString(t, inst, "spec", "forProvider", "serviceAccount", "email"); got != saEmail {
					t.Errorf("instance serviceAccount.email = %q, want %s", got, saEmail)
				}
				scopes := nestedSlice(t, inst, "spec", "forProvider", "serviceAccount", "scopes")
				assertSameSet(t, "instance serviceAccount.scopes", toStrings(t, scopes), []string{"https://www.googleapis.com/auth/cloud-platform"})

				assertSharedNetworkNIC(t, inst)

				if got := nestedString(t, inst, "spec", "providerConfigRef", "name"); got != providerConfigName {
					t.Errorf("instance providerConfigRef.name = %q, want %q", got, providerConfigName)
				}

				assertAccessConfig(t, inst, reservedAddr)

				instRes := resp.GetDesired().GetResources()["instance"]
				if instRes.GetReady() == fnv1.Ready_READY_FALSE {
					t.Errorf("instance Ready = READY_FALSE, want not-false once SA email and address are known")
				}

				status := compositeStatus(t, resp)
				assertExactStatusKeys(t, status, []string{"address", "serviceAccountEmail"})
				if got := digString(status, "address"); got != reservedAddr {
					t.Errorf("XR status.address = %q, want reserved address %q", got, reservedAddr)
				}
				if got := digString(status, "serviceAccountEmail"); got != saEmail {
					t.Errorf("XR status.serviceAccountEmail = %q, want %q", got, saEmail)
				}
			},
		},
		{
			name: "reserved rendering, enableOsLogin false",
			spec: gcpSpec(map[string]any{"type": "Reserved"}, map[string]any{"enableOsLogin": false}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
				"address":         observedAddress(t, "address", reservedAddr),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"address", "firewall", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})
				assertAccessConfig(t, desiredResource(t, resp, "instance"), reservedAddr)
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
				"address":           map[string]any{"type": "Ephemeral"},
				"wgListenPort":      51820,
				"serviceAccountId":  "gateway",
				"secretId":          gatewaySecretID,
				"members": []any{map[string]any{
					"name": "gateway-instance", "slot": 0, "tunnelAddress": "10.99.0.2/29",
					"kubernetesSecretName": "gateway-wg-key", "cloudSecretName": "secret",
					"cloudSecretVersionName": "secret-version", "cloudSecretIamMemberName": "secret-iam",
				}},
			},
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
				"instance":        observedInstance(t, ephemeralNatIP),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"firewall", "firewall-iap", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})

				inst := desiredResource(t, resp, "instance")
				assertSharedNetworkNIC(t, inst)
				if got := nestedString(t, inst, "spec", "forProvider", "desiredStatus"); got != "RUNNING" {
					t.Errorf("instance desiredStatus = %q, want RUNNING", got)
				}
				assertAccessConfig(t, inst, "")
				if got := nestedString(t, inst, "spec", "providerConfigRef", "name"); got != "default" {
					t.Errorf("instance providerConfigRef.name = %q, want default (providerConfigName omitted from spec)", got)
				}

				status := compositeStatus(t, resp)
				assertExactStatusKeys(t, status, []string{"address", "serviceAccountEmail"})
				if got := digString(status, "address"); got != ephemeralNatIP {
					t.Errorf("XR status.address = %q, want ephemeral natIp %q", got, ephemeralNatIP)
				}
			},
		},
		{
			name: "ephemeral rendering, enableOsLogin false",
			spec: gcpSpec(map[string]any{"type": "Ephemeral"}, map[string]any{"enableOsLogin": false}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
				"instance":        observedInstance(t, ephemeralNatIP),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"firewall", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})
				assertAccessConfig(t, desiredResource(t, resp, "instance"), "")
			},
		},
		{
			name: "external by ip renders no address",
			spec: gcpSpec(map[string]any{
				"type":     "External",
				"external": map[string]any{"ip": reservedAddr},
			}, nil),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"firewall", "firewall-iap", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})
				assertAccessConfig(t, desiredResource(t, resp, "instance"), reservedAddr)

				status := compositeStatus(t, resp)
				assertExactStatusKeys(t, status, []string{"address", "serviceAccountEmail"})
				if got := digString(status, "address"); got != reservedAddr {
					t.Errorf("XR status.address = %q, want the spec literal %q", got, reservedAddr)
				}
			},
		},
		{
			name: "external by ip, enableOsLogin false",
			spec: gcpSpec(map[string]any{
				"type":     "External",
				"external": map[string]any{"ip": reservedAddr},
			}, map[string]any{"enableOsLogin": false}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"firewall", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})
				assertAccessConfig(t, desiredResource(t, resp, "instance"), reservedAddr)
			},
		},
		{
			name: "external by name renders observe-only address",
			spec: gcpSpec(map[string]any{
				"type":     "External",
				"external": map[string]any{"name": externalAddrName},
			}, nil),
			observed: map[string]*fnv1.Resource{
				"service-account":  observedServiceAccount(t),
				"address-observed": observedAddress(t, "address-observed", reservedAddr),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"address-observed", "firewall", "firewall-iap", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})

				addr := desiredResource(t, resp, "address-observed")
				policies := nestedSlice(t, addr, "spec", "managementPolicies")
				assertSameSet(t, "address-observed managementPolicies", toStrings(t, policies), []string{"Observe"})
				if got := nestedString(t, addr, "metadata", "annotations", "crossplane.io/external-name"); got != externalAddrName {
					t.Errorf("address-observed external-name = %q, want %q", got, externalAddrName)
				}
				assertAddressForProvider(t, addr, map[string]any{"region": testRegion})
				if got := nestedString(t, addr, "spec", "providerConfigRef", "name"); got != providerConfigName {
					t.Errorf("address-observed providerConfigRef.name = %q, want %q", got, providerConfigName)
				}

				assertAccessConfig(t, desiredResource(t, resp, "instance"), reservedAddr)

				status := compositeStatus(t, resp)
				assertExactStatusKeys(t, status, []string{"address", "serviceAccountEmail"})
				if got := digString(status, "address"); got != reservedAddr {
					t.Errorf("XR status.address = %q, want observed address %q", got, reservedAddr)
				}
			},
		},
		{
			name: "first render withholds instance until address-observed reports an address",
			spec: gcpSpec(map[string]any{
				"type":     "External",
				"external": map[string]any{"name": externalAddrName},
			}, nil),
			observed: map[string]*fnv1.Resource{
				"service-account":  observedServiceAccount(t),
				"address-observed": observedAddress(t, "address-observed", ""),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"address-observed", "firewall", "firewall-iap",
					"secret", "secret-iam", "secret-version", "service-account",
				})
				assertExactStatusKeys(t, compositeStatus(t, resp), []string{"serviceAccountEmail"})
			},
		},
		{
			name: "first render withholds instance, enableOsLogin false",
			spec: gcpSpec(map[string]any{
				"type":     "External",
				"external": map[string]any{"name": externalAddrName},
			}, map[string]any{"enableOsLogin": false}),
			observed: map[string]*fnv1.Resource{
				"service-account":  observedServiceAccount(t),
				"address-observed": observedAddress(t, "address-observed", ""),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"address-observed", "firewall",
					"secret", "secret-iam", "secret-version", "service-account",
				})
				assertExactStatusKeys(t, compositeStatus(t, resp), []string{"serviceAccountEmail"})
			},
		},
		{
			name: "external by name, enableOsLogin false, admits the instance",
			spec: gcpSpec(map[string]any{
				"type":     "External",
				"external": map[string]any{"name": externalAddrName},
			}, map[string]any{"enableOsLogin": false}),
			observed: map[string]*fnv1.Resource{
				"service-account":  observedServiceAccount(t),
				"address-observed": observedAddress(t, "address-observed", reservedAddr),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"address-observed", "firewall", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})
				assertAccessConfig(t, desiredResource(t, resp, "instance"), reservedAddr)
				assertExactStatusKeys(t, compositeStatus(t, resp), []string{"address", "serviceAccountEmail"})
			},
		},
		{
			name: "observed instance keeps its own natIp until the target is known",
			spec: gcpSpec(map[string]any{"type": "Reserved"}, nil),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
				"instance":        observedInstance(t, priorNatIP),
				"address":         observedAddress(t, "address", ""),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"address", "firewall", "firewall-iap", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})
				assertAccessConfig(t, desiredResource(t, resp, "instance"), priorNatIP)
				status := compositeStatus(t, resp)
				assertExactStatusKeys(t, status, []string{"address", "serviceAccountEmail"})
				if got := digString(status, "address"); got != priorNatIP {
					t.Errorf("XR status.address = %q, want the observed natIp %q", got, priorNatIP)
				}
			},
		},
		{
			name: "observed instance without a reported NIC stays rendered while the target is unknown",
			spec: gcpSpec(map[string]any{"type": "Reserved"}, nil),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
				"instance":        observedInstance(t, ""),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"address", "firewall", "firewall-iap", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})
				assertAccessConfig(t, desiredResource(t, resp, "instance"), "")
				assertExactStatusKeys(t, compositeStatus(t, resp), []string{"serviceAccountEmail"})
			},
		},
		{
			name: "observed instance keeps its own service-account email until the service account reports",
			spec: gcpSpec(map[string]any{"type": "Reserved"}, nil),
			observed: map[string]*fnv1.Resource{
				"instance": observedInstanceWithServiceAccount(t, priorNatIP, priorSAEmail),
				"address":  observedAddress(t, "address", targetNatIP),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"address", "firewall", "firewall-iap", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})
				inst := desiredResource(t, resp, "instance")
				assertInstanceServiceAccount(t, inst, priorSAEmail)
				assertAccessConfig(t, inst, targetNatIP)
				assertSharedNetworkNIC(t, inst)
				fwSAs := nestedSlice(t, desiredResource(t, resp, "firewall"), "spec", "forProvider", "targetServiceAccounts")
				assertSameSet(t, "firewall targetServiceAccounts", toStrings(t, fwSAs), []string{priorSAEmail})
				iapSAs := nestedSlice(t, desiredResource(t, resp, "firewall-iap"), "spec", "forProvider", "targetServiceAccounts")
				assertSameSet(t, "firewall-iap targetServiceAccounts", toStrings(t, iapSAs), []string{priorSAEmail})
				iam := desiredResource(t, resp, "secret-iam")
				if got := nestedString(t, iam, "spec", "forProvider", "member"); got != "serviceAccount:"+priorSAEmail {
					t.Errorf("secret-iam member = %q, want serviceAccount:%s", got, priorSAEmail)
				}
				status := compositeStatus(t, resp)
				assertExactStatusKeys(t, status, []string{"address"})
				if got := digString(status, "address"); got != targetNatIP {
					t.Errorf("XR status.address = %q, want reserved address %q", got, targetNatIP)
				}
			},
		},
		{
			name: "observed instance adopts the reserved address once it reports",
			spec: gcpSpec(map[string]any{"type": "Reserved"}, nil),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
				"instance":        observedInstance(t, priorNatIP),
				"address":         observedAddress(t, "address", targetNatIP),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"address", "firewall", "firewall-iap", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})
				assertAccessConfig(t, desiredResource(t, resp, "instance"), targetNatIP)
				status := compositeStatus(t, resp)
				assertExactStatusKeys(t, status, []string{"address", "serviceAccountEmail"})
				if got := digString(status, "address"); got != targetNatIP {
					t.Errorf("XR status.address = %q, want reserved address %q", got, targetNatIP)
				}
			},
		},
		{
			name: "instance observed with no email source fails the render",
			spec: gcpSpec(map[string]any{"type": "Reserved"}, nil),
			observed: map[string]*fnv1.Resource{
				"service-account": observedResource(t, "service-account", map[string]any{
					"apiVersion": "cloudplatform.gcp.m.upbound.io/v1beta1",
					"kind":       "ServiceAccount",
					"status":     map[string]any{"atProvider": map[string]any{}},
				}),
				"instance": observedInstance(t, priorNatIP),
				"address":  observedAddress(t, "address", targetNatIP),
			},
			wantRenderErr: "instance observed without a service-account email",
		},
		{
			name:     "empty observed set renders the reserved pre-instance stack",
			spec:     gcpSpec(map[string]any{"type": "Reserved"}, nil),
			observed: map[string]*fnv1.Resource{},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{"address", "secret", "secret-version", "service-account"})
			},
		},
		{
			name:     "empty observed set renders the ephemeral pre-instance stack",
			spec:     gcpSpec(map[string]any{"type": "Ephemeral"}, nil),
			observed: map[string]*fnv1.Resource{},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{"secret", "secret-version", "service-account"})
			},
		},
		{
			name: "empty observed set renders the external-by-ip pre-instance stack",
			spec: gcpSpec(map[string]any{
				"type":     "External",
				"external": map[string]any{"ip": reservedAddr},
			}, nil),
			observed: map[string]*fnv1.Resource{},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{"secret", "secret-version", "service-account"})
			},
		},
		{
			name: "empty observed set renders the external-by-name pre-instance stack",
			spec: gcpSpec(map[string]any{
				"type":     "External",
				"external": map[string]any{"name": externalAddrName},
			}, nil),
			observed: map[string]*fnv1.Resource{},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{"address-observed", "secret", "secret-version", "service-account"})
			},
		},
		{
			name: "spot emits SPOT scheduling block",
			spec: gcpSpec(map[string]any{"type": "Ephemeral"}, map[string]any{
				"spot":          true,
				"enableOsLogin": false,
			}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				// OS Login is disabled on this spec, so IAP SSH has no way in and the
				// IAP firewall rule stays out of the desired set.
				assertExactDesiredNames(t, resp, []string{
					"firewall", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})

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
			},
		},
		{
			// A non-default wgListenPort and projectID must flow verbatim onto the instance
			// metadata, so keyfetch reads the per-Gateway value, not a chart-baked one.
			name: "non-default wgListenPort and projectID reach instance metadata",
			spec: gcpSpec(map[string]any{"type": "Ephemeral"}, map[string]any{
				"wgListenPort":     51999,
				"wgMTU":            1280,
				"wgGatewayAddress": "10.50.0.1",
				"wgLinkAddress":    "10.50.0.2",
				"wgSubnet":         "10.50.0.0/29",
				"projectID":        "other-project",
			}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"firewall", "firewall-iap", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})

				inst := desiredResource(t, resp, "instance")
				wantMeta := map[string]string{
					"wg-listen-port":  "51999",
					"wg-mtu":          "1280",
					"wg-link-address": "10.50.0.2",
					"project-id":      "other-project",
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
			spec: gcpSpec(map[string]any{"type": "Ephemeral"}, map[string]any{
				"wgGatewayAddress": "10.99.0.1",
				"wgLinkAddress":    "10.99.0.2",
				"wgSubnet":         "10.99.0.0/29",
				"projectID":        testProjectID,
				"trafficPolicy":    "local",
			}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"firewall", "firewall-iap", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})
				inst := desiredResource(t, resp, "instance")
				if got := nestedString(t, inst, "spec", "forProvider", "metadata", "traffic-policy"); got != "local" {
					t.Errorf("instance metadata traffic-policy = %q, want local", got)
				}
			},
		},
		{
			name: "the first not-ready composed resource publishes its message",
			spec: gcpSpec(map[string]any{"type": "Ephemeral"}, nil),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
				"instance":        observedInstance(t, "", condition("Synced", "False", "ReconcileError", "boom")),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				status := compositeStatus(t, resp)
				assertExactStatusKeys(t, status, []string{"message", "serviceAccountEmail"})
				if got := digString(status, "message"); got != "instance: boom" {
					t.Errorf("XR status.message = %q, want %q", got, "instance: boom")
				}
			},
		},
		{
			name: "two not-ready composed resources publish the lexically first name",
			spec: gcpSpec(map[string]any{"type": "Ephemeral"}, nil),
			observed: map[string]*fnv1.Resource{
				"secret": observedSecret(t, condition("Synced", "False", "ReconcileError", "secret boom")),
				"service-account": observedServiceAccount(t,
					condition("Synced", "False", "ReconcileError", "sa boom")),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				status := compositeStatus(t, resp)
				assertExactStatusKeys(t, status, []string{"message", "serviceAccountEmail"})
				if got := digString(status, "message"); got != "secret: secret boom" {
					t.Errorf("XR status.message = %q, want %q", got, "secret: secret boom")
				}
			},
		},
		{
			name: "ready composed resources publish no message",
			spec: gcpSpec(map[string]any{"type": "Ephemeral"}, nil),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t, condition("Ready", "True", "Available", "")),
				"instance":        observedInstance(t, ephemeralNatIP, condition("Ready", "True", "Available", "")),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactStatusKeys(t, compositeStatus(t, resp), []string{"address", "serviceAccountEmail"})
			},
		},
		{
			name: "an empty-message condition is skipped for a later real message",
			spec: gcpSpec(map[string]any{"type": "Ephemeral"}, nil),
			observed: map[string]*fnv1.Resource{
				"secret": observedSecret(t, condition("Ready", "False", "Creating", "")),
				"service-account": observedServiceAccount(t,
					condition("Synced", "False", "ReconcileError", "M")),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				status := compositeStatus(t, resp)
				assertExactStatusKeys(t, status, []string{"message", "serviceAccountEmail"})
				if got := digString(status, "message"); got != "service-account: M" {
					t.Errorf("XR status.message = %q, want %q", got, "service-account: M")
				}
			},
		},
		{
			name: "only empty-message conditions publish no message",
			spec: gcpSpec(map[string]any{"type": "Ephemeral"}, nil),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t, condition("Ready", "False", "Creating", "")),
				"instance":        observedInstance(t, ephemeralNatIP, condition("Ready", "False", "Creating", "")),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactStatusKeys(t, compositeStatus(t, resp), []string{"address", "serviceAccountEmail"})
			},
		},
		{
			name: "load balanced withholds backend and forwarding until observed",
			spec: lbSpec(nil),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					templateResourceName(lbTemplateRevision), "health-check-lb", "health-check-mig",
					"firewall-probe", "service-account", "firewall", "firewall-iap", "address",
				})
			},
		},
		{
			name:     "load_balanced_withholds_template_and_mig_until_service_account_email",
			spec:     lbSpec(nil),
			observed: map[string]*fnv1.Resource{},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{"address", "service-account"})
				assertExactStatusKeys(t, compositeStatus(t, resp), []string{})
			},
		},
		{
			name:     "single_instance_unchanged_without_load_balanced",
			spec:     gcpSpec(map[string]any{"type": "Reserved"}, nil),
			observed: map[string]*fnv1.Resource{"service-account": observedServiceAccount(t), "address": observedAddress(t, "address", reservedAddr)},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"address", "firewall", "firewall-iap", "instance",
					"secret", "secret-iam", "secret-version", "service-account",
				})
			},
		},
		{
			name: "load balanced template metadata includes user data",
			spec: lbSpec(map[string]any{"userData": "#cloud-config\n"}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				template := desiredResource(t, resp, templateResourceName(lbTemplateRevision))
				if got, want := nestedMap(t, template, "spec", "forProvider"), expectedTemplate(lbSpec(map[string]any{"userData": "#cloud-config\n"}), lbTemplateRevision).forProvider; !reflect.DeepEqual(got, want) {
					t.Errorf("template forProvider = %v, want %v", got, want)
				}
				if got, want := nestedMap(t, template, "spec", "forProvider", "metadata"), expectedTemplateMetadata("#cloud-config\n"); !reflect.DeepEqual(got, want) {
					t.Errorf("template metadata = %v, want %v", got, want)
				}
			},
		},
		{
			name: "load balanced template metadata omits empty user data",
			spec: lbSpec(map[string]any{"userData": ""}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				template := desiredResource(t, resp, templateResourceName(lbTemplateRevision))
				if got, want := nestedMap(t, template, "spec", "forProvider", "metadata"), expectedTemplateMetadata(""); !reflect.DeepEqual(got, want) {
					t.Errorf("template metadata = %v, want %v", got, want)
				}
			},
		},
		{
			name: "two members render two triples with explicit refs",
			spec: lbSpec(map[string]any{
				"members": []any{
					map[string]any{
						"name": "gw-vm-a1b2", "slot": 0, "tunnelAddress": "10.99.0.2/29",
						"kubernetesSecretName": "gw-uid-a1b2", "cloudSecretName": "gw-uid-a1b2-secret",
						"cloudSecretVersionName": "gw-uid-a1b2-version", "cloudSecretIamMemberName": "gw-uid-a1b2-iam",
					},
					map[string]any{
						"name": "gw-vm-c3d4", "slot": 1, "tunnelAddress": "10.99.0.3/29",
						"kubernetesSecretName": "gw-uid-c3d4", "cloudSecretName": "gw-uid-c3d4-secret",
						"cloudSecretVersionName": "gw-uid-c3d4-version", "cloudSecretIamMemberName": "gw-uid-c3d4-iam",
					},
				},
			}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					templateResourceName(lbTemplateRevision), "health-check-lb", "health-check-mig", "firewall-probe",
					"service-account", "firewall", "firewall-iap", "address", "gw-uid-a1b2-secret", "gw-uid-a1b2-version", "gw-uid-a1b2-iam",
					"gw-uid-c3d4-secret", "gw-uid-c3d4-version", "gw-uid-c3d4-iam",
				})
				for _, m := range []struct{ name, cloudSecretName, cloudSecretVersionName, cloudSecretIAMMemberName, kubernetesSecretName string }{
					{"gw-vm-a1b2", "gw-uid-a1b2-secret", "gw-uid-a1b2-version", "gw-uid-a1b2-iam", "gw-uid-a1b2"},
					{"gw-vm-c3d4", "gw-uid-c3d4-secret", "gw-uid-c3d4-version", "gw-uid-c3d4-iam", "gw-uid-c3d4"},
				} {
					wantSelector := map[string]any{
						"matchControllerRef": true,
						"matchLabels":        map[string]any{"wgnet.dev/member": m.name},
					}
					secret := desiredResource(t, resp, m.cloudSecretName)
					if got, want := nestedMap(t, secret, "metadata", "labels"), map[string]any{"wgnet.dev/member": m.name}; !reflect.DeepEqual(got, want) {
						t.Errorf("secret %s metadata.labels = %v, want %v", m.cloudSecretName, got, want)
					}
					secVer := desiredResource(t, resp, m.cloudSecretVersionName)
					if got := nestedMap(t, secVer, "spec", "forProvider", "secretSelector"); !reflect.DeepEqual(got, wantSelector) {
						t.Errorf("secret-version %s secretSelector = %v, want %v", m.cloudSecretVersionName, got, wantSelector)
					}
					if got := nestedString(t, secVer, "spec", "forProvider", "secretDataSecretRef", "name"); got != m.kubernetesSecretName {
						t.Errorf("secret-version %s secretDataSecretRef.name = %q, want %q", m.cloudSecretVersionName, got, m.kubernetesSecretName)
					}
					if got := nestedString(t, secVer, "spec", "forProvider", "secretDataSecretRef", "key"); got != "bundle" {
						t.Errorf("secret-version %s secretDataSecretRef.key = %q, want bundle", m.cloudSecretVersionName, got)
					}
					iam := desiredResource(t, resp, m.cloudSecretIAMMemberName)
					if got := nestedMap(t, iam, "spec", "forProvider", "secretIdSelector"); !reflect.DeepEqual(got, wantSelector) {
						t.Errorf("secret IAM member %s secretIdSelector = %v, want %v", m.cloudSecretIAMMemberName, got, wantSelector)
					}
				}
			},
		},
		{
			name: "mig policy shape",
			spec: lbSpec(map[string]any{
				"zones":      []any{"us-central1-a", "us-central1-b"},
				"targetSize": 3,
			}),
			observed: map[string]*fnv1.Resource{
				"service-account":                        observedServiceAccount(t),
				templateResourceName(lbTemplateRevision): observedTemplate(t, lbSpec(nil), lbTemplateRevision),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				mig := desiredResource(t, resp, "mig")
				wantPolicy := map[string]any{
					"type":                       "PROACTIVE",
					"replacementMethod":          "RECREATE",
					"maxSurgeFixed":              float64(0),
					"maxUnavailableFixed":        float64(2),
					"instanceRedistributionType": "NONE",
				}
				if got := nestedMap(t, mig, "spec", "initProvider", "updatePolicy"); !reflect.DeepEqual(got, wantPolicy) {
					t.Errorf("mig updatePolicy = %v, want %v", got, wantPolicy)
				}
				zones := nestedSlice(t, mig, "spec", "forProvider", "distributionPolicyZones")
				assertSameSet(t, "mig distributionPolicyZones", toStrings(t, zones), []string{"us-central1-a", "us-central1-b"})
			},
		},
		{
			name: "autohealing policy withheld until observed",
			spec: lbSpec(nil),
			observed: map[string]*fnv1.Resource{
				"service-account":                        observedServiceAccount(t),
				templateResourceName(lbTemplateRevision): observedTemplate(t, lbSpec(nil), lbTemplateRevision),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					templateResourceName(lbTemplateRevision), "mig", "health-check-lb", "health-check-mig",
					"firewall-probe", "service-account", "firewall", "firewall-iap", "address",
				})
				mig := desiredResource(t, resp, "mig")
				if got, want := nestedMap(t, mig, "spec", "forProvider"), expectedMIGForProvider(nil); !reflect.DeepEqual(got, want) {
					t.Errorf("mig forProvider = %v, want %v", got, want)
				}
				if got, want := nestedMap(t, mig, "spec", "initProvider"), expectedMIGInitProvider(); !reflect.DeepEqual(got, want) {
					t.Errorf("mig initProvider = %v, want %v", got, want)
				}
			},
		},
		{
			name: "autohealing policy populated once observed",
			spec: lbSpec(nil),
			observed: map[string]*fnv1.Resource{
				"service-account":                        observedServiceAccount(t),
				templateResourceName(lbTemplateRevision): observedTemplate(t, lbSpec(nil), lbTemplateRevision),
				"health-check-mig":                       observedHealthCheck(t, "health-check-mig", migHealthCheckSelfLink),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				mig := desiredResource(t, resp, "mig")
				autoHealingPolicies := map[string]any{
					"healthCheck":     migHealthCheckSelfLink,
					"initialDelaySec": float64(900),
				}
				if got, want := nestedMap(t, mig, "spec", "forProvider"), expectedMIGForProvider(autoHealingPolicies); !reflect.DeepEqual(got, want) {
					t.Errorf("mig forProvider = %v, want %v", got, want)
				}
				if got, want := nestedMap(t, mig, "spec", "initProvider"), expectedMIGInitProvider(); !reflect.DeepEqual(got, want) {
					t.Errorf("mig initProvider = %v, want %v", got, want)
				}
			},
		},
		{
			name: "template revision renders new template on change",
			spec: lbSpec(map[string]any{"templateRevision": "revAAAAAAA1"}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				name1 := templateResourceName("revAAAAAAA1")
				assertExactDesiredNames(t, resp, []string{
					name1, "health-check-lb", "health-check-mig", "firewall-probe",
					"service-account", "firewall", "firewall-iap", "address",
				})

				run2Spec := lbSpec(map[string]any{"templateRevision": "revBBBBBBB2"})
				run2Observed := map[string]*fnv1.Resource{
					"service-account": observedServiceAccount(t),
					name1: observedTemplateFromDesired(t, name1, desiredResource(t, resp, name1),
						templateSelfLink("revAAAAAAA1")),
					"mig": observedMigWithVersion(t, map[string]any{"isReached": false},
						templateSelfLink("revAAAAAAA1")),
				}
				resp2 := runComposition(t, rf, template, run2Spec, run2Observed)
				name2 := templateResourceName("revBBBBBBB2")
				assertExactDesiredNames(t, resp2, []string{
					name1, name2, "mig", "health-check-lb", "health-check-mig", "firewall-probe",
					"service-account", "firewall", "firewall-iap", "address",
				})
				assertMIGVersion(t, resp2, templateSelfLink("revAAAAAAA1"))

				resp3 := runComposition(t, rf, template, run2Spec, map[string]*fnv1.Resource{
					"service-account": observedServiceAccount(t),
					name1: observedTemplateFromDesired(t, name1, desiredResource(t, resp, name1),
						templateSelfLink("revAAAAAAA1")),
					name2: observedTemplateFromDesired(t, name2, desiredResource(t, resp2, name2),
						templateSelfLink("revBBBBBBB2")),
				})
				assertExactDesiredNames(t, resp3, []string{
					name1, name2, "mig", "health-check-lb", "health-check-mig", "firewall-probe",
					"service-account", "firewall", "firewall-iap", "address",
				})
				assertMIGVersion(t, resp3, templateSelfLink("revBBBBBBB2"))

				resp4 := runComposition(t, rf, template, run2Spec, map[string]*fnv1.Resource{
					"service-account": observedServiceAccount(t),
					name1: observedTemplateFromDesired(t, name1, desiredResource(t, resp, name1),
						templateSelfLink("revAAAAAAA1")),
					name2: observedTemplateFromDesired(t, name2, desiredResource(t, resp3, name2),
						templateSelfLink("revBBBBBBB2")),
					"mig": observedMigWithVersion(t, map[string]any{"isReached": true},
						templateSelfLink("revBBBBBBB2")),
				})
				assertExactDesiredNames(t, resp4, []string{
					name2, "mig", "health-check-lb", "health-check-mig", "firewall-probe",
					"service-account", "firewall", "firewall-iap", "address",
				})
				assertMIGVersion(t, resp4, templateSelfLink("revBBBBBBB2"))
			},
		},
		{
			name: "template revisions with shared prefix render distinct resources",
			spec: lbSpec(map[string]any{"templateRevision": "revSHARED1"}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				name1 := templateResourceName("revSHARED1")
				name2 := templateResourceName("revSHARED2")
				assertExactDesiredNames(t, resp, []string{
					name1, "health-check-lb", "health-check-mig", "firewall-probe",
					"service-account", "firewall", "firewall-iap", "address",
				})
				run2Spec := lbSpec(map[string]any{"templateRevision": "revSHARED2"})
				resp2 := runComposition(t, rf, template, run2Spec, map[string]*fnv1.Resource{
					"service-account": observedServiceAccount(t),
					name1: observedTemplateFromDesired(t, name1, desiredResource(t, resp, name1),
						templateSelfLink("revSHARED1")),
					"mig": observedMigWithVersion(t, map[string]any{"isReached": false},
						templateSelfLink("revSHARED1")),
				})
				assertSameSet(t, "template resource names", templateNamesIn(resp2), []string{name1, name2})
				assertMIGVersion(t, resp2, templateSelfLink("revSHARED1"))
				resp3 := runComposition(t, rf, template, run2Spec, map[string]*fnv1.Resource{
					"service-account": observedServiceAccount(t),
					name1: observedTemplateFromDesired(t, name1, desiredResource(t, resp, name1),
						templateSelfLink("revSHARED1")),
					name2: observedTemplateFromDesired(t, name2, desiredResource(t, resp2, name2),
						templateSelfLink("revSHARED2")),
				})
				assertMIGVersion(t, resp3, templateSelfLink("revSHARED2"))
			},
		},
		{
			name: "template revision unaffected by observation only change",
			spec: lbSpec(map[string]any{"templateRevision": "revSSSSSSS1"}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				name1 := templateResourceName("revSSSSSSS1")
				assertExactDesiredNames(t, resp, []string{
					name1, "health-check-lb", "health-check-mig", "firewall-probe",
					"service-account", "firewall", "firewall-iap", "address",
				})

				run2Spec := lbSpec(map[string]any{"templateRevision": "revSSSSSSS1"})
				run2Observed := map[string]*fnv1.Resource{
					"service-account": observedServiceAccount(t, condition("Ready", "True", "Available", "")),
					name1: observedTemplateFromDesired(t, name1, desiredResource(t, resp, name1),
						templateSelfLink("revSSSSSSS1")),
				}
				resp2 := runComposition(t, rf, template, run2Spec, run2Observed)
				assertSameSet(t, "run 2 template resource names", templateNamesIn(resp2), []string{name1})
				assertMIGVersion(t, resp2, templateSelfLink("revSSSSSSS1"))
			},
		},
		{
			name: "multiple retained templates use observed mig version",
			spec: lbSpec(map[string]any{"templateRevision": "revCCCCCCC3"}),
			observed: map[string]*fnv1.Resource{
				"service-account":                   observedServiceAccount(t),
				templateResourceName("revAAAAAAA1"): observedTemplate(t, lbSpec(map[string]any{"templateRevision": "revAAAAAAA1"}), "revAAAAAAA1"),
				templateResourceName("revZZZZZZZ9"): observedTemplate(t, lbSpec(map[string]any{"templateRevision": "revZZZZZZZ9"}), "revZZZZZZZ9"),
				"mig": observedMigWithVersion(t, map[string]any{"isReached": false},
					templateSelfLink("revAAAAAAA1")),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					templateResourceName("revAAAAAAA1"), templateResourceName("revZZZZZZZ9"),
					templateResourceName("revCCCCCCC3"), "mig", "health-check-lb", "health-check-mig",
					"firewall-probe", "service-account", "firewall", "firewall-iap", "address",
				})
				assertMIGVersion(t, resp, templateSelfLink("revAAAAAAA1"))
			},
		},
		{
			name: "template retained when observed mig targets previous template",
			spec: lbSpec(map[string]any{"templateRevision": "revCCCCCCC3"}),
			observed: map[string]*fnv1.Resource{
				"service-account":                   observedServiceAccount(t),
				templateResourceName("revOLDOLDO0"): observedTemplate(t, lbSpec(map[string]any{"templateRevision": "revOLDOLDO0"}), "revOLDOLDO0"),
				templateResourceName("revCCCCCCC3"): observedTemplate(t, lbSpec(map[string]any{"templateRevision": "revCCCCCCC3"}), "revCCCCCCC3"),
				"mig": observedMigWithVersion(t, map[string]any{"isReached": true},
					templateSelfLink("revOLDOLDO0")),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertSameSet(t, "template resource names", templateNamesIn(resp),
					[]string{templateResourceName("revOLDOLDO0"), templateResourceName("revCCCCCCC3")})
			},
		},
		{
			name: "template retained when current mig target is not reached",
			spec: lbSpec(map[string]any{"templateRevision": "revEEEEEEE5"}),
			observed: map[string]*fnv1.Resource{
				"service-account":                   observedServiceAccount(t),
				templateResourceName("revOLDOLDO2"): observedTemplate(t, lbSpec(map[string]any{"templateRevision": "revOLDOLDO2"}), "revOLDOLDO2"),
				templateResourceName("revEEEEEEE5"): observedTemplate(t, lbSpec(map[string]any{"templateRevision": "revEEEEEEE5"}), "revEEEEEEE5"),
				"mig": observedMigWithVersion(t, map[string]any{"isReached": false},
					templateSelfLink("revEEEEEEE5")),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertSameSet(t, "template resource names", templateNamesIn(resp),
					[]string{templateResourceName("revOLDOLDO2"), templateResourceName("revEEEEEEE5")})
			},
		},
		{
			name: "template retired when current mig target is reached",
			spec: lbSpec(map[string]any{"templateRevision": "revDDDDDDD4"}),
			observed: map[string]*fnv1.Resource{
				"service-account":                   observedServiceAccount(t),
				templateResourceName("revOLDOLDO1"): observedTemplate(t, lbSpec(map[string]any{"templateRevision": "revOLDOLDO1"}), "revOLDOLDO1"),
				templateResourceName("revDDDDDDD4"): observedTemplate(t, lbSpec(map[string]any{"templateRevision": "revDDDDDDD4"}), "revDDDDDDD4"),
				"mig": observedMigWithVersion(t, map[string]any{"isReached": true},
					templateSelfLink("revDDDDDDD4")),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertSameSet(t, "template resource names", templateNamesIn(resp), []string{templateResourceName("revDDDDDDD4")})
			},
		},
		{
			name: "template retained when current template is unobserved",
			spec: lbSpec(map[string]any{"templateRevision": "revFFFFFF6"}),
			observed: map[string]*fnv1.Resource{
				"service-account":                   observedServiceAccount(t),
				templateResourceName("revOLDOLDO3"): observedTemplate(t, lbSpec(map[string]any{"templateRevision": "revOLDOLDO3"}), "revOLDOLDO3"),
				"mig": observedMigWithVersion(t, map[string]any{"isReached": true},
					templateSelfLink("revOLDOLDO3")),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertSameSet(t, "template resource names", templateNamesIn(resp),
					[]string{templateResourceName("revOLDOLDO3"), templateResourceName("revFFFFFF6")})
			},
		},
		{
			name: "template retained when mig is unobserved",
			spec: lbSpec(map[string]any{"templateRevision": "revGGGGGGG7"}),
			observed: map[string]*fnv1.Resource{
				"service-account":                   observedServiceAccount(t),
				templateResourceName("revOLDOLDO4"): observedTemplate(t, lbSpec(map[string]any{"templateRevision": "revOLDOLDO4"}), "revOLDOLDO4"),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertSameSet(t, "template resource names", templateNamesIn(resp),
					[]string{templateResourceName("revOLDOLDO4"), templateResourceName("revGGGGGGG7")})
			},
		},
		{
			name: "health checks rendered shape",
			spec: lbSpec(map[string]any{"healthPort": 27000}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				for name, want := range map[string]map[string]any{
					"health-check-lb":  {"checkIntervalSec": float64(5), "timeoutSec": float64(5), "healthyThreshold": float64(2), "unhealthyThreshold": float64(2)},
					"health-check-mig": {"checkIntervalSec": float64(30), "timeoutSec": float64(10), "healthyThreshold": float64(2), "unhealthyThreshold": float64(10)},
				} {
					hc := desiredResource(t, resp, name)
					httpCheck := nestedMap(t, hc, "spec", "forProvider", "httpHealthCheck")
					wantHTTP := map[string]any{"port": float64(27000), "requestPath": "/forwarded-healthz"}
					if !reflect.DeepEqual(httpCheck, wantHTTP) {
						t.Errorf("%s httpHealthCheck = %v, want %v", name, httpCheck, wantHTTP)
					}
					forProvider := nestedMap(t, hc, "spec", "forProvider")
					for k, v := range want {
						if got := forProvider[k]; got != v {
							t.Errorf("%s forProvider[%s] = %v, want %v", name, k, got, v)
						}
					}
				}
			},
		},
		{
			name: "health checks rendered shape, non-default port",
			spec: lbSpec(map[string]any{"healthPort": 8181}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				for name, want := range map[string]map[string]any{
					"health-check-lb":  {"checkIntervalSec": float64(5), "timeoutSec": float64(5), "healthyThreshold": float64(2), "unhealthyThreshold": float64(2)},
					"health-check-mig": {"checkIntervalSec": float64(30), "timeoutSec": float64(10), "healthyThreshold": float64(2), "unhealthyThreshold": float64(10)},
				} {
					hc := desiredResource(t, resp, name)
					httpCheck := nestedMap(t, hc, "spec", "forProvider", "httpHealthCheck")
					wantHTTP := map[string]any{"port": float64(8181), "requestPath": "/forwarded-healthz"}
					if !reflect.DeepEqual(httpCheck, wantHTTP) {
						t.Errorf("%s httpHealthCheck = %v, want %v", name, httpCheck, wantHTTP)
					}
					forProvider := nestedMap(t, hc, "spec", "forProvider")
					for k, v := range want {
						if got := forProvider[k]; got != v {
							t.Errorf("%s forProvider[%s] = %v, want %v", name, k, got, v)
						}
					}
				}

				probe := desiredResource(t, resp, "firewall-probe")
				wantAllow := []any{map[string]any{"protocol": "tcp", "ports": []any{"8181"}}}
				if got := nestedSlice(t, probe, "spec", "forProvider", "allow"); !reflect.DeepEqual(got, wantAllow) {
					t.Errorf("firewall-probe allow = %v, want %v", got, wantAllow)
				}
			},
		},
		{
			name: "probe firewall exact ranges",
			spec: lbSpec(nil),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				probe := desiredResource(t, resp, "firewall-probe")
				ranges := nestedSlice(t, probe, "spec", "forProvider", "sourceRanges")
				assertSameSet(t, "firewall-probe sourceRanges", toStrings(t, ranges),
					[]string{"35.191.0.0/16", "209.85.204.0/22", "130.211.0.0/22", "209.85.152.0/22"})

				fw := desiredResource(t, resp, "firewall")
				wantAllow := []any{map[string]any{"protocol": "udp", "ports": []any{"51820"}}}
				if got := nestedSlice(t, fw, "spec", "forProvider", "allow"); !reflect.DeepEqual(got, wantAllow) {
					t.Errorf("firewall allow = %v, want %v", got, wantAllow)
				}
			},
		},
		{
			name: "forwarding rule and backend shape",
			spec: lbSpec(map[string]any{"sessionAffinity": "CLIENT_IP"}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
				"address":         observedAddress(t, "address", reservedAddr),
				"mig": observedResource(t, "mig", map[string]any{
					"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
					"kind":       "RegionInstanceGroupManager",
					"spec": map[string]any{"forProvider": map[string]any{
						"version": []any{map[string]any{"instanceTemplate": templateSelfLink(lbTemplateRevision)}},
					}},
					"status": map[string]any{"atProvider": map[string]any{"instanceGroup": "https://compute.googleapis.com/compute/v1/projects/wgnet-test/regions/us-central1/instanceGroups/gw"}},
				}),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"address", "backend-service", "firewall", "firewall-iap", "firewall-probe",
					"forwarding-rule", "health-check-lb", "health-check-mig", "mig", "service-account",
					templateResourceName(lbTemplateRevision),
				})
				fr := desiredResource(t, resp, "forwarding-rule")
				wantFR := map[string]any{
					"region":              testRegion,
					"loadBalancingScheme": "EXTERNAL",
					"ipProtocol":          "L3_DEFAULT",
					"allPorts":            true,
					"ipAddress":           reservedAddr,
					"backendServiceSelector": map[string]any{
						"matchControllerRef": true,
						"matchLabels":        map[string]any{"wgnet.dev/component": "backend-service"},
					},
				}
				if got := nestedMap(t, fr, "spec", "forProvider"); !reflect.DeepEqual(got, wantFR) {
					t.Errorf("forwarding-rule forProvider = %v, want %v", got, wantFR)
				}

				bs := desiredResource(t, resp, "backend-service")
				wantBS := map[string]any{
					"region":              testRegion,
					"loadBalancingScheme": "EXTERNAL",
					"protocol":            "UNSPECIFIED",
					"sessionAffinity":     "CLIENT_IP",
					"backend": []any{map[string]any{
						"balancingMode": "CONNECTION",
						"group":         "https://compute.googleapis.com/compute/v1/projects/wgnet-test/regions/us-central1/instanceGroups/gw",
					}},
					"healthChecksSelector": map[string]any{
						"matchControllerRef": true,
						"matchLabels":        map[string]any{"wgnet.dev/component": "health-check-lb"},
					},
				}
				if got := nestedMap(t, bs, "spec", "forProvider"); !reflect.DeepEqual(got, wantBS) {
					t.Errorf("backend-service forProvider = %v, want %v", got, wantBS)
				}

				healthCheck := desiredResource(t, resp, "health-check-lb")
				if got, want := nestedMap(t, healthCheck, "metadata", "labels"), map[string]any{"wgnet.dev/component": "health-check-lb"}; !reflect.DeepEqual(got, want) {
					t.Errorf("health-check-lb metadata.labels = %v, want %v", got, want)
				}
				if got, want := nestedMap(t, bs, "metadata", "labels"), map[string]any{"wgnet.dev/component": "backend-service"}; !reflect.DeepEqual(got, want) {
					t.Errorf("backend-service metadata.labels = %v, want %v", got, want)
				}
			},
		},
		{
			name: "load-balanced external by ip, service account observed",
			spec: lbSpec(map[string]any{
				"address": map[string]any{"type": "External", "external": map[string]any{"ip": "203.0.113.10"}},
			}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"firewall", "firewall-iap", "firewall-probe",
					"forwarding-rule", "health-check-lb", "health-check-mig", "service-account",
					templateResourceName(lbTemplateRevision),
				})
				fr := desiredResource(t, resp, "forwarding-rule")
				if got := nestedString(t, fr, "spec", "forProvider", "ipAddress"); got != "203.0.113.10" {
					t.Errorf("forwarding-rule ipAddress = %q, want %q", got, "203.0.113.10")
				}
				status := compositeStatus(t, resp)
				assertExactStatusKeys(t, status, []string{"address", "serviceAccountEmail"})
				if got := digString(status, "address"); got != "203.0.113.10" {
					t.Errorf("XR status.address = %q, want %q", got, "203.0.113.10")
				}
			},
		},
		{
			name: "load-balanced external by name, empty observed set",
			spec: lbSpec(map[string]any{
				"address": map[string]any{"type": "External", "external": map[string]any{"name": "edge-ip"}},
			}),
			observed: map[string]*fnv1.Resource{},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{"address-observed", "service-account"})

				addr := desiredResource(t, resp, "address-observed")
				policies := nestedSlice(t, addr, "spec", "managementPolicies")
				assertSameSet(t, "address-observed managementPolicies", toStrings(t, policies), []string{"Observe"})
				if got := nestedString(t, addr, "metadata", "annotations", "crossplane.io/external-name"); got != "edge-ip" {
					t.Errorf("address-observed external-name = %q, want %q", got, "edge-ip")
				}
				assertAddressForProvider(t, addr, map[string]any{"region": testRegion})

				assertExactStatusKeys(t, compositeStatus(t, resp), []string{})
			},
		},
		{
			name: "load-balanced external by name, address-observed reports",
			spec: lbSpec(map[string]any{
				"address": map[string]any{"type": "External", "external": map[string]any{"name": "edge-ip"}},
			}),
			observed: map[string]*fnv1.Resource{
				"service-account":  observedServiceAccount(t),
				"address-observed": observedAddress(t, "address-observed", "203.0.113.11"),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"address-observed", "firewall", "firewall-iap", "firewall-probe",
					"forwarding-rule", "health-check-lb", "health-check-mig", "service-account",
					templateResourceName(lbTemplateRevision),
				})
				fr := desiredResource(t, resp, "forwarding-rule")
				if got := nestedString(t, fr, "spec", "forProvider", "ipAddress"); got != "203.0.113.11" {
					t.Errorf("forwarding-rule ipAddress = %q, want %q", got, "203.0.113.11")
				}
				status := compositeStatus(t, resp)
				assertExactStatusKeys(t, status, []string{"address", "serviceAccountEmail"})
				if got := digString(status, "address"); got != "203.0.113.11" {
					t.Errorf("XR status.address = %q, want %q", got, "203.0.113.11")
				}
			},
		},
		{
			name: "load-balanced external by name, address-observed not yet reporting",
			spec: lbSpec(map[string]any{
				"address": map[string]any{"type": "External", "external": map[string]any{"name": "edge-ip"}},
			}),
			observed: map[string]*fnv1.Resource{
				"service-account":  observedServiceAccount(t),
				"address-observed": observedAddress(t, "address-observed", ""),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				assertExactDesiredNames(t, resp, []string{
					"address-observed", "firewall", "firewall-iap", "firewall-probe",
					"health-check-lb", "health-check-mig", "service-account",
					templateResourceName(lbTemplateRevision),
				})
				assertExactStatusKeys(t, compositeStatus(t, resp), []string{"serviceAccountEmail"})
			},
		},
		{
			name: "observed mig name published to status",
			spec: lbSpec(nil),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
				"mig":             observedMigWithName(t, "gw-mig-observed-1"),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				status := compositeStatus(t, resp)
				if got := digString(status, "migName"); got != "gw-mig-observed-1" {
					t.Errorf("XR status.migName = %q, want gw-mig-observed-1", got)
				}
			},
		},
		{
			name: "observed instance name published to status",
			spec: gcpSpec(map[string]any{"type": "Reserved"}, nil),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
				"address":         observedAddress(t, "address", reservedAddr),
				"instance":        observedInstanceWithName(t, reservedAddr, "gw-instance-observed-1"),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				status := compositeStatus(t, resp)
				if got := digString(status, "instanceName"); got != "gw-instance-observed-1" {
					t.Errorf("XR status.instanceName = %q, want gw-instance-observed-1", got)
				}
			},
		},
		{
			name: "creating instance withholds name from status",
			spec: gcpSpec(map[string]any{"type": "Reserved"}, nil),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
				"address":         observedAddress(t, "address", reservedAddr),
				"instance": observedResource(t, "instance", map[string]any{
					"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
					"kind":       "Instance",
					"metadata": map[string]any{"annotations": map[string]any{
						"crossplane.io/external-name": "gw-instance-creating-1",
					}},
					"status": map[string]any{"atProvider": map[string]any{
						"networkInterface": []any{
							map[string]any{"accessConfig": []any{map[string]any{"natIp": reservedAddr}}},
						},
					}},
				}),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				want := map[string]any{"address": reservedAddr, "serviceAccountEmail": saEmail}
				if got := compositeStatus(t, resp); !reflect.DeepEqual(got, want) {
					t.Errorf("XR status = %v, want %v", got, want)
				}
			},
		},
		{
			name: "single instance metadata startup script revision",
			spec: gcpSpec(map[string]any{"type": "Ephemeral"}, map[string]any{
				"templateRevision": "abc123",
				"wgGatewayAddress": "10.99.0.1",
				"wgLinkAddress":    "10.99.0.2",
				"wgSubnet":         "10.99.0.0/29",
				"projectID":        testProjectID,
			}),
			observed: map[string]*fnv1.Resource{
				"service-account": observedServiceAccount(t),
			},
			assert: func(t *testing.T, resp *fnv1.RunFunctionResponse) {
				t.Helper()
				inst := desiredResource(t, resp, "instance")
				startup := nestedString(t, inst, "spec", "forProvider", "metadataStartupScript")
				if !strings.Contains(startup, "abc123") {
					t.Errorf("instance metadataStartupScript = %q, want it to contain abc123", startup)
				}
				wantMetadata := map[string]any{
					"secret-id": gatewaySecretID, "wg-listen-port": "51820", "wg-mtu": "1380",
					"wg-link-address": "10.99.0.2", "traffic-policy": "cluster",
					"project-id": testProjectID, "disable-legacy-endpoints": "true",
					"block-project-ssh-keys": "true", "enable-oslogin": "TRUE",
				}
				if got := nestedMap(t, inst, "spec", "forProvider", "metadata"); !reflect.DeepEqual(got, wantMetadata) {
					t.Errorf("instance metadata = %v, want %v", got, wantMetadata)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if (tt.assert == nil) == (tt.wantRenderErr == "") {
				t.Fatalf("row %q must set exactly one of assert and wantRenderErr", tt.name)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			req := rf.buildRequestFor(t, template, "XGatewayGCP", tt.spec, tt.observed)
			resp, err := rf.client.RunFunction(ctx, req)
			if tt.wantRenderErr != "" {
				assertRenderFailed(t, resp, err, tt.wantRenderErr)
				return
			}
			if err != nil {
				t.Fatalf("RunFunction: %v", err)
			}
			for _, res := range resp.GetResults() {
				if res.GetSeverity() == fnv1.Severity_SEVERITY_FATAL {
					t.Fatalf("function returned fatal result: %s", res.GetMessage())
				}
			}
			assertComposedResourcesMatchProviderSchemas(t, resp)
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

	assertComposedResourcesMatchProviderSchemas(t, resp)

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
	if providerSchemaEnv != nil {
		if err := providerSchemaEnv.Stop(); err != nil {
			log.Printf("stop provider schema envtest: %v", err)
		}
	}
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
	annotations, ok := meta["annotations"].(map[string]any)
	if !ok {
		annotations = map[string]any{}
	}
	annotations["crossplane.io/composition-resource-name"] = name
	meta["annotations"] = annotations
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

// assertRenderFailed fails unless the render reported an error whose text contains want,
// either as the RPC error or as a fatal result.
func assertRenderFailed(t *testing.T, resp *fnv1.RunFunctionResponse, err error, want string) {
	t.Helper()
	got := ""
	if err != nil {
		got = err.Error()
	}
	for _, res := range resp.GetResults() {
		if res.GetSeverity() == fnv1.Severity_SEVERITY_FATAL {
			got = res.GetMessage()
		}
	}
	if got == "" {
		t.Fatalf("render succeeded with desired resources %v, want an error containing %q", desiredKeys(resp), want)
	}
	if !strings.Contains(got, want) {
		t.Fatalf("render error = %q, want it to contain %q", got, want)
	}
}

// assertSharedNetworkNIC asserts the instance's primary NIC attaches directly to
// the shared VPC by name and carries no subnetwork wiring.
func assertSharedNetworkNIC(t *testing.T, inst map[string]any) {
	t.Helper()
	nics := nestedSlice(t, inst, "spec", "forProvider", "networkInterface")
	if len(nics) != 1 {
		t.Fatalf("instance has %d networkInterface entries, want exactly 1", len(nics))
	}
	nic0, ok := nics[0].(map[string]any)
	if !ok {
		t.Fatalf("networkInterface[0] is %T, want map", nics[0])
	}
	if got, _ := nic0["network"].(string); got != sharedNetworkName {
		t.Errorf("instance networkInterface[0].network = %q, want shared network %q", got, sharedNetworkName)
	}
	wantKeys := []string{"accessConfig", "network"}
	if got := slices.Sorted(maps.Keys(nic0)); !slices.Equal(got, wantKeys) {
		t.Errorf("instance networkInterface[0] keys = %v, want %v", got, wantKeys)
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

// gcpSpec returns the XGatewayGCP spec the address cases share, carrying the given
// address block with per-case overrides applied on top.
func gcpSpec(address, overrides map[string]any) map[string]any {
	spec := map[string]any{
		"region":             testRegion,
		"zone":               testRegion + "-a",
		"machineType":        "e2-small",
		"sharedNetworkName":  sharedNetworkName,
		"providerConfigName": providerConfigName,
		"wgListenPort":       51820,
		"wgMTU":              1380,
		"serviceAccountId":   "gateway",
		"secretId":           gatewaySecretID,
		"members": []any{map[string]any{
			"name": "gateway-instance", "slot": 0, "tunnelAddress": "10.99.0.2/29",
			"kubernetesSecretName": "gateway-wg-key", "cloudSecretName": "secret",
			"cloudSecretVersionName": "secret-version", "cloudSecretIamMemberName": "secret-iam",
		}},
		"address": address,
	}
	maps.Copy(spec, overrides)
	return spec
}

// lbSpec returns the shared load-balanced XGatewayGCP spec with required fields.
// Per-case overrides are applied on top.
func lbSpec(overrides map[string]any) map[string]any {
	spec := map[string]any{
		"region":             testRegion,
		"zone":               testRegion + "-a",
		"machineType":        "e2-small",
		"sharedNetworkName":  sharedNetworkName,
		"providerConfigName": providerConfigName,
		"wgListenPort":       51820,
		"wgMTU":              1380,
		"serviceAccountId":   "gateway",
		"secretId":           gatewaySecretID,
		"loadBalanced":       true,
		"sessionAffinity":    "NONE",
		"targetSize":         1,
		"zones":              []any{testRegion + "-a"},
		"healthPort":         27000,
		"templateRevision":   lbTemplateRevision,
		"members":            []any{},
	}
	maps.Copy(spec, overrides)
	return spec
}

func expectedTemplateMetadata(userData string) map[string]any {
	metadata := map[string]any{
		"secret-id":                gatewaySecretID,
		"wg-listen-port":           "51820",
		"wg-mtu":                   "1380",
		"traffic-policy":           "cluster",
		"disable-legacy-endpoints": "true",
		"block-project-ssh-keys":   "true",
		"enable-oslogin":           "TRUE",
	}
	if userData != "" {
		metadata["user-data"] = userData
	}
	return metadata
}

type expectedTemplateResource struct {
	externalName string
	forProvider  map[string]any
}

func expectedTemplate(spec map[string]any, revision string) expectedTemplateResource {
	userData, _ := spec["userData"].(string)
	forProvider := map[string]any{
		"namePrefix":            fmt.Sprintf("%s-%s", xrName, revision),
		"machineType":           spec["machineType"],
		"metadataStartupScript": fmt.Sprintf("# gateway-bootstrap-revision: %s", revision),
		"disk": []any{map[string]any{
			"boot":       true,
			"autoDelete": true,
			"diskSizeGb": float64(20),
		}},
		"metadata": expectedTemplateMetadata(userData),
		"networkInterface": []any{map[string]any{
			"network":      sharedNetworkName,
			"accessConfig": []any{map[string]any{}},
		}},
		"serviceAccount": map[string]any{
			"email":  saEmail,
			"scopes": []any{"https://www.googleapis.com/auth/cloud-platform"},
		},
	}
	return expectedTemplateResource{
		externalName: fmt.Sprintf("%s-%s", xrName, revision),
		forProvider:  forProvider,
	}
}

func assertMIGVersion(t *testing.T, resp *fnv1.RunFunctionResponse, selfLink string) {
	t.Helper()
	mig := desiredResource(t, resp, "mig")
	want := []any{map[string]any{"instanceTemplate": selfLink}}
	if got := nestedSlice(t, mig, "spec", "forProvider", "version"); !reflect.DeepEqual(got, want) {
		t.Errorf("mig version = %v, want %v", got, want)
	}
}

func templateSelfLink(revision string) string {
	return fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/wgnet-test/global/instanceTemplates/%s-%s", xrName, revision)
}

func expectedMIGForProvider(autoHealingPolicies map[string]any) map[string]any {
	forProvider := map[string]any{
		"name":                        fmt.Sprintf("%s-mig", xrName),
		"region":                      testRegion,
		"baseInstanceName":            xrName,
		"distributionPolicyZones":     []any{testRegion + "-a"},
		"targetSize":                  float64(1),
		"listManagedInstancesResults": "PAGINATED",
		"version":                     []any{map[string]any{"instanceTemplate": templateSelfLink(lbTemplateRevision)}},
		"statefulExternalIp": []any{map[string]any{
			"interfaceName": "nic0",
			"deleteRule":    "ON_PERMANENT_INSTANCE_DELETION",
		}},
		"instanceLifecyclePolicy": map[string]any{"defaultActionOnFailure": "REPAIR"},
	}
	if autoHealingPolicies != nil {
		forProvider["autoHealingPolicies"] = autoHealingPolicies
	}
	return forProvider
}

func expectedMIGInitProvider() map[string]any {
	return map[string]any{
		"updatePolicy": map[string]any{
			"type":                       "PROACTIVE",
			"replacementMethod":          "RECREATE",
			"maxSurgeFixed":              float64(0),
			"maxUnavailableFixed":        float64(1),
			"instanceRedistributionType": "NONE",
		},
	}
}

func templateResourceName(revision string) string {
	return "template-" + revision
}

// templateNamesIn returns every desired resource name with the "template-" prefix.
func templateNamesIn(resp *fnv1.RunFunctionResponse) []string {
	var names []string
	for _, name := range desiredKeys(resp) {
		if strings.HasPrefix(name, "template-") {
			names = append(names, name)
		}
	}
	return names
}

// runComposition renders template against spec/observed and fails the test on
// a transport error or a fatal function result.
func runComposition(t *testing.T, rf *runFunction, template string, spec map[string]any, observed map[string]*fnv1.Resource) *fnv1.RunFunctionResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req := rf.buildRequestFor(t, template, "XGatewayGCP", spec, observed)
	resp, err := rf.client.RunFunction(ctx, req)
	if err != nil {
		t.Fatalf("RunFunction: %v", err)
	}
	for _, res := range resp.GetResults() {
		if res.GetSeverity() == fnv1.Severity_SEVERITY_FATAL {
			t.Fatalf("function returned fatal result: %s", res.GetMessage())
		}
	}
	assertComposedResourcesMatchProviderSchemas(t, resp)
	return resp
}

// condition builds a status.conditions entry. An empty message is omitted, the shape
// Crossplane publishes for Creating and Unavailable.
func condition(ctype, status, reason, message string) map[string]any {
	c := map[string]any{"type": ctype, "status": status, "reason": reason}
	if message != "" {
		c["message"] = message
	}
	return c
}

// observedServiceAccount is the observed service-account carrying the email the
// template gates the firewall, secret IAM member and instance on.
func observedServiceAccount(t *testing.T, conditions ...map[string]any) *fnv1.Resource {
	t.Helper()
	return observedResource(t, "service-account", map[string]any{
		"apiVersion": "cloudplatform.gcp.m.upbound.io/v1beta1",
		"kind":       "ServiceAccount",
		"status": withConditions(map[string]any{
			"atProvider": map[string]any{"email": saEmail},
		}, conditions),
	})
}

func observedSecret(t *testing.T, conditions ...map[string]any) *fnv1.Resource {
	t.Helper()
	return observedResource(t, "secret", map[string]any{
		"apiVersion": "secretmanager.gcp.m.upbound.io/v1beta1",
		"kind":       "Secret",
		"status":     withConditions(map[string]any{"atProvider": map[string]any{}}, conditions),
	})
}

// observedAddress is the observed Address under composition-resource-name name. An empty
// ip leaves status.atProvider without an address, the state before GCP allocates one.
func observedAddress(t *testing.T, name, ip string, conditions ...map[string]any) *fnv1.Resource {
	t.Helper()
	atProvider := map[string]any{}
	if ip != "" {
		atProvider["address"] = ip
	}
	return observedResource(t, name, map[string]any{
		"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
		"kind":       "Address",
		"status":     withConditions(map[string]any{"atProvider": atProvider}, conditions),
	})
}

// observedHealthCheck is an observed RegionHealthCheck reporting selfLink, the value the
// mig's autoHealingPolicies.healthCheck is built from verbatim once observed.
func observedHealthCheck(t *testing.T, name, selfLink string) *fnv1.Resource {
	t.Helper()
	return observedResource(t, name, map[string]any{
		"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
		"kind":       "RegionHealthCheck",
		"status":     map[string]any{"atProvider": map[string]any{"selfLink": selfLink}},
	})
}

// observedMigWithName is an observed RegionInstanceGroupManager reporting its GCP-assigned
// name, which the composition publishes into the XR's status.migName.
func observedMigWithVersion(t *testing.T, versionTarget map[string]any, instanceTemplate string) *fnv1.Resource {
	t.Helper()
	return observedResource(t, "mig", map[string]any{
		"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
		"kind":       "RegionInstanceGroupManager",
		"spec": map[string]any{"forProvider": map[string]any{
			"version": []any{map[string]any{"instanceTemplate": instanceTemplate}},
		}},
		"status": map[string]any{"atProvider": map[string]any{
			"status":  []any{map[string]any{"versionTarget": []any{versionTarget}}},
			"version": []any{map[string]any{"instanceTemplate": instanceTemplate}},
		}},
	})
}

func observedMigWithName(t *testing.T, name string) *fnv1.Resource {
	t.Helper()
	return observedResource(t, "mig", map[string]any{
		"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
		"kind":       "RegionInstanceGroupManager",
		"spec": map[string]any{"forProvider": map[string]any{
			"version": []any{map[string]any{"instanceTemplate": templateSelfLink(lbTemplateRevision)}},
		}},
		"status": map[string]any{"atProvider": map[string]any{"name": name}},
	})
}

func observedTemplateFromDesired(t *testing.T, name string, body map[string]any, selfLink string) *fnv1.Resource {
	t.Helper()
	body["status"] = map[string]any{"atProvider": map[string]any{"selfLink": selfLink}}
	return observedResource(t, name, body)
}

func observedTemplate(t *testing.T, spec map[string]any, revision string) *fnv1.Resource {
	t.Helper()
	want := expectedTemplate(spec, revision)
	return observedResource(t, templateResourceName(revision), map[string]any{
		"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
		"kind":       "InstanceTemplate",
		"metadata": map[string]any{"annotations": map[string]any{
			"crossplane.io/external-name": want.externalName,
		}},
		"spec":   map[string]any{"forProvider": want.forProvider},
		"status": map[string]any{"atProvider": map[string]any{"selfLink": templateSelfLink(revision)}},
	})
}

// observedInstanceWithName is an observed Instance whose external name the composition
// publishes into status.instanceName.
func observedInstanceWithName(t *testing.T, natIP, name string) *fnv1.Resource {
	t.Helper()
	return observedResource(t, "instance", map[string]any{
		"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
		"kind":       "Instance",
		"metadata": map[string]any{"annotations": map[string]any{
			"crossplane.io/external-name": name,
		}},
		"status": map[string]any{
			"atProvider": map[string]any{
				"id": "projects/" + testProjectID + "/zones/" + testRegion + "-a/instances/" + name,
				"networkInterface": []any{
					map[string]any{"accessConfig": []any{map[string]any{"natIp": natIP}}},
				},
			},
		},
	})
}

// observedInstance is the observed Instance. An empty natIP leaves status.atProvider
// without a networkInterface, the state before the VM reports its NIC.
func observedInstance(t *testing.T, natIP string, conditions ...map[string]any) *fnv1.Resource {
	t.Helper()
	atProvider := map[string]any{}
	if natIP != "" {
		atProvider["networkInterface"] = []any{
			map[string]any{"accessConfig": []any{map[string]any{"natIp": natIP}}},
		}
	}
	return observedResource(t, "instance", map[string]any{
		"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
		"kind":       "Instance",
		"status":     withConditions(map[string]any{"atProvider": atProvider}, conditions),
	})
}

// observedInstanceWithServiceAccount is the observed Instance reporting both a natIp and
// the service-account email GCP attached to the running VM.
func observedInstanceWithServiceAccount(t *testing.T, natIP, email string) *fnv1.Resource {
	t.Helper()
	return observedResource(t, "instance", map[string]any{
		"apiVersion": "compute.gcp.m.upbound.io/v1beta1",
		"kind":       "Instance",
		"status": map[string]any{
			"atProvider": map[string]any{
				"networkInterface": []any{
					map[string]any{"accessConfig": []any{map[string]any{"natIp": natIP}}},
				},
				"serviceAccount": map[string]any{"email": email},
			},
		},
	})
}

// assertInstanceServiceAccount fails unless the rendered instance's serviceAccount block is
// exactly the given email plus the cloud-platform scope.
func assertInstanceServiceAccount(t *testing.T, inst map[string]any, email string) {
	t.Helper()
	got := nestedMap(t, inst, "spec", "forProvider", "serviceAccount")
	want := map[string]any{
		"email":  email,
		"scopes": []any{"https://www.googleapis.com/auth/cloud-platform"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("instance serviceAccount = %v, want %v", got, want)
	}
}

// assertAddressForProvider fails unless the rendered Address's spec.forProvider is exactly want.
func assertAddressForProvider(t *testing.T, addr map[string]any, want map[string]any) {
	t.Helper()
	got := nestedMap(t, addr, "spec", "forProvider")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("address forProvider = %v, want %v", got, want)
	}
}

func withConditions(status map[string]any, conditions []map[string]any) map[string]any {
	if len(conditions) == 0 {
		return status
	}
	entries := make([]any, 0, len(conditions))
	for _, c := range conditions {
		entries = append(entries, c)
	}
	status["conditions"] = entries
	return status
}

// assertExactDesiredNames fails unless resp's desired resource names are exactly want,
// compared as sets: an omission and a leak both fail the same way.
func assertExactDesiredNames(t *testing.T, resp *fnv1.RunFunctionResponse, want []string) {
	t.Helper()
	assertSameSet(t, "desired resource names", desiredKeys(resp), want)
}

// assertExactStatusKeys fails unless the XR's desired status carries exactly want as its
// top-level keys.
func assertExactStatusKeys(t *testing.T, status map[string]any, want []string) {
	t.Helper()
	got := make([]string, 0, len(status))
	for k := range status {
		got = append(got, k)
	}
	assertSameSet(t, "XR status keys", got, want)
}

// assertAccessConfig fails unless the instance's primary NIC carries exactly one
// accessConfig entry, holding natIp want, or nothing at all when want is empty.
func assertAccessConfig(t *testing.T, inst map[string]any, want string) {
	t.Helper()
	acs := nestedSlice(t, inst, "spec", "forProvider", "networkInterface", "0", "accessConfig")
	if len(acs) != 1 {
		t.Fatalf("instance accessConfig = %v, want exactly one entry", acs)
	}
	got, ok := acs[0].(map[string]any)
	if !ok {
		t.Fatalf("instance accessConfig[0] is %T, want map", acs[0])
	}
	wantEntry := map[string]any{}
	if want != "" {
		wantEntry["natIp"] = want
	}
	if !reflect.DeepEqual(got, wantEntry) {
		t.Errorf("instance accessConfig[0] = %v, want %v", got, wantEntry)
	}
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

// allowProtocols returns the protocol of every firewall allow rule, so a case can
// pin the exact rule set the template opens.
func allowProtocols(t *testing.T, allow []any) []string {
	t.Helper()
	out := make([]string, 0, len(allow))
	for _, raw := range allow {
		rule, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("allow rule is %T, want map", raw)
		}
		proto, ok := rule["protocol"].(string)
		if !ok {
			t.Fatalf("allow rule protocol is %T, want string", rule["protocol"])
		}
		out = append(out, proto)
	}
	return out
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

func nestedMap(t *testing.T, m map[string]any, path ...string) map[string]any {
	t.Helper()
	v := nested(t, m, path...)
	mm, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("value at %v is %T, want map", path, v)
	}
	return mm
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
