// Command xrdgen generates typed Go views of the XGateway XRD's spec and status
// subtrees. The XRD's openAPIV3Schema is plain JSON Schema, which oapi-codegen
// can consume once wrapped in a minimal OpenAPI 3 document; this tool performs
// that wrapping and drives oapi-codegen.
//
// It is a build-time tool: failures abort with a clear message and a non-zero
// exit rather than returning errors to a caller.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"
)

func main() {
	xrdPath := flag.String("xrd", "k8s/charts/wireguard-gateway-operator/crossplane/gcp/xgateway-xrd.yaml", "path to the XGateway XRD YAML")
	outDir := flag.String("out", "pkg/crossplane/gcp", "directory for the generated Go file")
	flag.Parse()

	if err := run(*xrdPath, *outDir); err != nil {
		fmt.Fprintf(os.Stderr, "xrdgen: %v\n", err)
		os.Exit(1)
	}
}

func run(xrdPath, outDir string) error {
	kind, specSchema, statusSchema, err := extractSchemas(xrdPath)
	if err != nil {
		return err
	}

	doc := openAPIDoc(specSchema, statusSchema)
	docJSON, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal openapi doc: %w", err)
	}

	// oapi-codegen infers the input format from the file extension, so the temp
	// file must end in .json (or .yaml).
	tmp, err := os.CreateTemp("", "xrdgen-*.json")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(docJSON); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	outFile := filepath.Join(outDir, strings.ToLower(kind)+".gen.go")
	// skip-prune keeps the XGatewaySpec/XGatewayStatus component schemas: without
	// it oapi-codegen drops every schema not referenced by an operation, and the
	// doc deliberately has no paths.
	cmd := exec.Command("go", "tool", "oapi-codegen",
		"-generate", "types,skip-prune",
		"-package", "gcp",
		"-o", outFile,
		tmp.Name(),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run oapi-codegen: %w", err)
	}
	return nil
}

// extractSchemas reads the XRD and returns its composite kind (spec.names.kind)
// along with the spec and status JSON-schema subtrees from
// spec.versions[0].schema.openAPIV3Schema.properties.
func extractSchemas(xrdPath string) (kind string, specSchema, statusSchema map[string]any, err error) {
	raw, err := os.ReadFile(xrdPath)
	if err != nil {
		return "", nil, nil, fmt.Errorf("read xrd %q: %w", xrdPath, err)
	}

	var xrd map[string]any
	if err := yaml.Unmarshal(raw, &xrd); err != nil {
		return "", nil, nil, fmt.Errorf("parse xrd yaml: %w", err)
	}

	names, err := digMap(xrd, "spec", "names")
	if err != nil {
		return "", nil, nil, err
	}
	kind, ok := names["kind"].(string)
	if !ok || kind == "" {
		return "", nil, nil, fmt.Errorf("spec.names.kind is missing or not a non-empty string")
	}

	versions, err := digSlice(xrd, "spec", "versions")
	if err != nil {
		return "", nil, nil, err
	}
	if len(versions) == 0 {
		return "", nil, nil, fmt.Errorf("xrd has no spec.versions")
	}
	v0, ok := versions[0].(map[string]any)
	if !ok {
		return "", nil, nil, fmt.Errorf("spec.versions[0] is not a mapping")
	}

	props, err := digMap(v0, "schema", "openAPIV3Schema", "properties")
	if err != nil {
		return "", nil, nil, err
	}

	specSchema, err = childMap(props, "spec")
	if err != nil {
		return "", nil, nil, err
	}
	statusSchema, err = childMap(props, "status")
	if err != nil {
		return "", nil, nil, err
	}
	return kind, specSchema, statusSchema, nil
}

// openAPIDoc wraps the spec and status schemas in the smallest OpenAPI 3
// document oapi-codegen will accept, exposing them as the XGatewaySpec and
// XGatewayStatus component schemas.
func openAPIDoc(specSchema, statusSchema map[string]any) map[string]any {
	return map[string]any{
		"openapi": "3.0.0",
		"info": map[string]any{
			"title":   "cyno",
			"version": "v1alpha1",
		},
		"paths": map[string]any{},
		"components": map[string]any{
			"schemas": map[string]any{
				"XGatewaySpec":   specSchema,
				"XGatewayStatus": statusSchema,
			},
		},
	}
}

func dig(m map[string]any, keys ...string) (any, error) {
	cur := any(m)
	for i, k := range keys {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%v is not a mapping", keys[:i])
		}
		next, ok := asMap[k]
		if !ok {
			return nil, fmt.Errorf("missing key %v", keys[:i+1])
		}
		cur = next
	}
	return cur, nil
}

func digMap(m map[string]any, keys ...string) (map[string]any, error) {
	v, err := dig(m, keys...)
	if err != nil {
		return nil, err
	}
	out, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%v is not a mapping", keys)
	}
	return out, nil
}

func digSlice(m map[string]any, keys ...string) ([]any, error) {
	v, err := dig(m, keys...)
	if err != nil {
		return nil, err
	}
	out, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%v is not a sequence", keys)
	}
	return out, nil
}

func childMap(m map[string]any, key string) (map[string]any, error) {
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("missing key %q", key)
	}
	out, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("key %q is not a mapping", key)
	}
	return out, nil
}
