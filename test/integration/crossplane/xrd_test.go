package crossplane

import (
	"reflect"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestXGatewayGCPSchemaSecretID(t *testing.T) {
	var xrd map[string]any
	if err := yaml.Unmarshal([]byte(readChartFile(t, "crossplane/gcp/xgateway-xrd.yaml")), &xrd); err != nil {
		t.Fatalf("parse XRD: %v", err)
	}

	spec := nestedMap(t, nestedMap(t, nestedMap(t, nestedMap(t, xrd, "spec"), "versions", "0"), "schema", "openAPIV3Schema"), "properties", "spec")
	properties := nestedMap(t, spec, "properties")
	tests := []struct {
		name string
		got  any
		want any
	}{
		{name: "required fields", got: nestedSlice(t, spec, "required"), want: []any{"region", "zone", "machineType", "sharedNetworkName", "wgListenPort", "wgMTU", "secretId"}},
		{name: "secret ID minimum length", got: nested(t, properties, "secretId", "minLength"), want: float64(1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !reflect.DeepEqual(tt.got, tt.want) {
				t.Errorf("schema value = %v, want %v", tt.got, tt.want)
			}
		})
	}
}
