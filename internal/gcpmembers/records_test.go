package gcpmembers

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestNameResourceNames(t *testing.T) {
	cases := []struct {
		name         string
		gatewayUID   string
		project      string
		instanceName string
		wantErr      bool
	}{
		{
			name:         "well_formed_name_derives_all_four_names",
			gatewayUID:   "abc-123",
			project:      "proj-1",
			instanceName: "gw-web-xyz9",
		},
		{
			name:         "naming_length_bound_rejected",
			gatewayUID:   "abc-123",
			project:      "proj-1",
			instanceName: strings.Repeat("a", 300),
			wantErr:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			names, err := NameResourceNames(tc.gatewayUID, tc.project, tc.instanceName)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NameResourceNames(%q, %q, %q) = %+v, nil; want a non-nil error", tc.gatewayUID, tc.project, tc.instanceName, names)
				}
				return
			}
			if err != nil {
				t.Fatalf("NameResourceNames(%q, %q, %q) returned unexpected error: %v", tc.gatewayUID, tc.project, tc.instanceName, err)
			}
			want := "gw-abc-123-proj-1-gw-web-xyz9"
			gotNames := ManagedResourceNames{
				KubernetesSecretName:     want,
				CloudSecretName:          want,
				CloudSecretVersionName:   want + "-version",
				CloudSecretIAMMemberName: want + "-iam",
			}
			if names != gotNames {
				t.Fatalf("NameResourceNames(%q, %q, %q) = %+v, want %+v", tc.gatewayUID, tc.project, tc.instanceName, names, gotNames)
			}
		})
	}
}

func TestRecordSecretRoundTrip(t *testing.T) {
	priv, pub := testKeypair(t)
	cases := []struct {
		name string
		rec  Record
	}{
		{
			name: "full_record_round_trips_byte_identical",
			rec: Record{
				Name:            "gw-web-xyz9",
				Zone:            "us-central1-a",
				Slot:            3,
				PrivateKey:      priv,
				PublicKey:       pub,
				TunnelAddress:   "10.99.0.4",
				SubnetPrefix:    29,
				PeerPublicKey:   "link-pub",
				PeerAllowedIPs:  "10.99.0.2/32",
				ExternalAddress: "203.0.113.9",
				InstanceID:      "1234567890",
				Revision:        "rev-1",
				DepartureCount:  2,
				GatewayUID:      types.UID("gw-uid-1"),
				Project:         "proj-1",
			},
		},
		{
			name: "pending_confirmation_round_trips",
			rec: Record{
				Name:                "gw-web-abcd",
				Slot:                0,
				PrivateKey:          priv,
				PublicKey:           pub,
				TunnelAddress:       "10.99.0.2",
				SubnetPrefix:        29,
				PeerPublicKey:       "link-pub",
				PeerAllowedIPs:      "10.99.0.3/32",
				PendingConfirmation: true,
				GatewayUID:          types.UID("gw-uid-2"),
				Project:             "proj-2",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secret, err := secretFromRecord("default", "my-gateway", "secret-name", tc.rec)
			if err != nil {
				t.Fatalf("secretFromRecord(...) returned unexpected error: %v", err)
			}
			secret.UID = types.UID("secret-uid-1")
			secret.ResourceVersion = "42"

			got, err := recordFromSecret(secret)
			if err != nil {
				t.Fatalf("recordFromSecret(...) returned unexpected error: %v", err)
			}

			want := tc.rec
			want.UID = types.UID("secret-uid-1")
			want.ResourceVersion = "42"

			if got != want {
				t.Fatalf("recordFromSecret(secretFromRecord(rec)) = %+v, want %+v", got, want)
			}
		})
	}
}

// TestBundlePayload pins the exact JSON the record Secret carries under the "bundle" key,
// which the composition republishes verbatim and the VM boot script parses.
func TestBundlePayload(t *testing.T) {
	priv, pub := testKeypair(t)
	rec := Record{
		Name:           "gw-web-xyz9",
		Slot:           2,
		PrivateKey:     priv,
		PublicKey:      pub,
		TunnelAddress:  "10.99.0.4",
		SubnetPrefix:   29,
		PeerPublicKey:  "link-pub",
		PeerAllowedIPs: "10.99.0.2/32",
		GatewayUID:     types.UID("gw-uid-1"),
		Project:        "proj-1",
	}

	secret, err := secretFromRecord("default", "my-gateway", "secret-name", rec)
	if err != nil {
		t.Fatalf("secretFromRecord(...) returned unexpected error: %v", err)
	}

	var got map[string]string
	if err := json.Unmarshal(secret.Data["bundle"], &got); err != nil {
		t.Fatalf("decoding the bundle payload returned unexpected error: %v", err)
	}
	want := map[string]string{
		"privateKey":     priv,
		"address":        "10.99.0.4/29",
		"slot":           "2",
		"peerPublicKey":  "link-pub",
		"peerAllowedIPs": "10.99.0.2/32",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bundle payload = %#v, want %#v", got, want)
	}
}

func TestSecretFromRecordSetsOwnerReference(t *testing.T) {
	rec := Record{
		Name:       "gw-web-xyz9",
		GatewayUID: types.UID("gw-uid-1"),
		Project:    "proj-1",
	}
	secret, err := secretFromRecord("default", "my-gateway", "secret-name", rec)
	if err != nil {
		t.Fatalf("secretFromRecord(...) returned unexpected error: %v", err)
	}

	if len(secret.OwnerReferences) != 1 {
		t.Fatalf("secretFromRecord(...).OwnerReferences has %d entries, want exactly 1: %+v", len(secret.OwnerReferences), secret.OwnerReferences)
	}
	ref := secret.OwnerReferences[0]
	if ref.APIVersion != "wgnet.dev/v1alpha1" || ref.Kind != "Gateway" || ref.Name != "my-gateway" || ref.UID != types.UID("gw-uid-1") {
		t.Fatalf("secretFromRecord(...).OwnerReferences[0] = %+v, want APIVersion wgnet.dev/v1alpha1, Kind Gateway, Name my-gateway, UID gw-uid-1", ref)
	}
	if ref.Controller == nil || !*ref.Controller || ref.BlockOwnerDeletion == nil || !*ref.BlockOwnerDeletion {
		t.Fatalf("secretFromRecord(...).OwnerReferences[0] = %+v, want Controller and BlockOwnerDeletion both true", ref)
	}
	if secret.Type != corev1.SecretTypeOpaque {
		t.Fatalf("secretFromRecord(...).Type = %v, want %v", secret.Type, corev1.SecretTypeOpaque)
	}
	if _, ok := secret.Data["bundle"]; !ok {
		t.Fatalf("secretFromRecord(...).Data = %+v, want a \"bundle\" key", secret.Data)
	}
}
