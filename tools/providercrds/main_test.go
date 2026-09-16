package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitDocuments(t *testing.T) {
	for _, tt := range []struct {
		name string
		data string
		want []string
	}{
		{name: "separators and empty documents", data: "one\n---  \n\n---\ntwo\n", want: []string{"one\n", "two\n"}},
		{name: "only content", data: "one\n", want: []string{"one\n"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := splitDocuments([]byte(tt.data))
			if len(got) != len(tt.want) {
				t.Fatalf("documents = %q, want %q", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("document %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSelectCRDs(t *testing.T) {
	const stream = `kind: CustomResourceDefinition
metadata:
  name: wanted.compute.gcp.m.upbound.io
---
kind: CustomResourceDefinition
metadata:
  name: ignored.compute.gcp.m.upbound.io
---
kind: ConfigMap
metadata:
  name: other
`
	for _, tt := range []struct {
		name    string
		docs    []string
		wanted  []string
		wantErr string
	}{
		{name: "wanted CRD", docs: splitDocuments([]byte(stream)), wanted: []string{"wanted.compute.gcp.m.upbound.io"}},
		{name: "duplicate CRD", docs: splitDocuments([]byte(stream + "---\nkind: CustomResourceDefinition\nmetadata:\n  name: wanted.compute.gcp.m.upbound.io\n")), wanted: []string{"wanted.compute.gcp.m.upbound.io"}, wantErr: "appears twice"},
		{name: "missing CRD", docs: splitDocuments([]byte(stream)), wanted: []string{"missing.compute.gcp.m.upbound.io"}, wantErr: "missing.compute.gcp.m.upbound.io"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectCRDs(tt.docs, tt.wanted)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got[tt.wanted[0]] == "" {
				t.Errorf("selected CRDs = %v", got)
			}
		})
	}
}

func TestPackageForCRD(t *testing.T) {
	for _, tt := range []struct{ name, crd, want string }{
		{name: "compute", crd: "instances.compute.gcp.m.upbound.io", want: "provider-gcp-compute"},
		{name: "cloud platform", crd: "serviceaccounts.cloudplatform.gcp.m.upbound.io", want: "provider-gcp-cloudplatform"},
		{name: "secret manager", crd: "secrets.secretmanager.gcp.m.upbound.io", want: "provider-gcp-secretmanager"},
		{name: "invalid group", crd: "things.example.org"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := packageForCRD(tt.crd)
			if tt.want == "" {
				if err == nil {
					t.Fatal("packageForCRD returned no error")
				}
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("packageForCRD = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestCollectPackages(t *testing.T) {
	for _, tt := range []struct {
		name, values string
		wantErr      string
	}{
		{name: "equal tags", values: "a: xpkg.upbound.io/upbound/provider-family-gcp:v2.5.4\nb: [xpkg.upbound.io/upbound/provider-gcp-compute:v2.5.4, xpkg.upbound.io/upbound/provider-gcp-cloudplatform:v2.5.4]\nc: xpkg.upbound.io/upbound/provider-gcp-secretmanager:v2.5.4\n"},
		{name: "mismatched tags", values: "a: xpkg.upbound.io/upbound/provider-gcp-compute:v2.5.4\nb: xpkg.upbound.io/upbound/provider-gcp-secretmanager:v2.5.5\n", wantErr: "v2.5.5"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "values.yaml")
			if err := os.WriteFile(path, []byte(tt.values), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := collectPackages(t.Context(), path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
