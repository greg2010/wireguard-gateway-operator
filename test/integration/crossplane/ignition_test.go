package crossplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"
)

// ignitionStorageFile is the subset of an Ignition storage.files entry the chart
// assertions read.
type ignitionStorageFile struct {
	Path     string `json:"path"`
	Mode     int    `json:"mode"`
	Contents struct {
		Source string `json:"source"`
	} `json:"contents"`
}

// ignitionConfig is the subset of the rendered Ignition config the chart
// assertions read.
type ignitionConfig struct {
	Storage struct {
		Files []ignitionStorageFile `json:"files"`
	} `json:"storage"`
}

// TestIgnitionStorageFiles renders through helm rather than reading files/ directly, so a
// file dropped from the template's list fails here even though its source still ships.
func TestIgnitionStorageFiles(t *testing.T) {
	files := renderIgnition(t).Storage.Files

	for _, tc := range []struct {
		name     string
		path     string
		mode     int
		contains []string
	}{
		{
			name: "renders the os login authorized keys drop-in",
			path: "/etc/ssh/sshd_config.d/10-google-oslogin.conf",
			mode: 420,
			// Sorting before the image's own 20-systemd-userdb.conf is what makes
			// OS Login keys win, so the assertion pins the command and its user.
			contains: []string{"google_authorized_keys", "AuthorizedKeysCommandUser root"},
		},
		{
			name:     "renders the keyfetch boot script",
			path:     "/opt/gateway/keyfetch.sh",
			mode:     493,
			contains: []string{"fetch_metadata_attr", "fetch_instance_attr"},
		},
		{
			name:     "renders the nftables ruleset template",
			path:     "/etc/nftables/gateway.nft",
			mode:     420,
			contains: []string{"table inet gateway"},
		},
		{
			name:     "renders the forwarding sysctls",
			path:     "/etc/sysctl.d/50-gateway-forward.conf",
			mode:     420,
			contains: []string{"net.ipv4.ip_forward"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, ok := storageFile(files, tc.path)
			if !ok {
				t.Fatalf("rendered ignition has no storage file %s; it has %v", tc.path, storagePaths(files))
			}
			if file.Mode != tc.mode {
				t.Errorf("storage file %s has mode %d, want %d", tc.path, file.Mode, tc.mode)
			}
			contents := decodeStorageContents(t, file)
			for _, want := range tc.contains {
				if !strings.Contains(contents, want) {
					t.Errorf("storage file %s does not contain %q:\n%s", tc.path, want, contents)
				}
			}
		})
	}
}

func storageFile(files []ignitionStorageFile, path string) (ignitionStorageFile, bool) {
	for _, f := range files {
		if f.Path == path {
			return f, true
		}
	}
	return ignitionStorageFile{}, false
}

func storagePaths(files []ignitionStorageFile) []string {
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	return paths
}

func decodeStorageContents(t *testing.T, file ignitionStorageFile) string {
	t.Helper()

	encoded, ok := strings.CutPrefix(file.Contents.Source, "data:;base64,")
	if !ok {
		t.Fatalf("storage file %s contents source %q is not an inline base64 data URL", file.Path, file.Contents.Source)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode storage file %s contents: %v", file.Path, err)
	}
	return string(raw)
}

// renderIgnition reads the Ignition back from the ConfigMap the operator Deployment
// sources it from, so the chart's own wiring is part of what the assertions cover.
func renderIgnition(t *testing.T) ignitionConfig {
	t.Helper()

	var cfg ignitionConfig
	if err := json.Unmarshal([]byte(renderUserData(t)), &cfg); err != nil {
		t.Fatalf("rendered userData is not an Ignition JSON config: %v", err)
	}
	return cfg
}

func renderUserData(t *testing.T) string {
	t.Helper()

	for doc := range strings.SplitSeq(helmTemplate(t), "\n---\n") {
		var obj struct {
			Kind string            `json:"kind"`
			Data map[string]string `json:"data"`
		}
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			t.Fatalf("parse rendered manifest: %v\n%s", err, doc)
		}
		if obj.Kind != "ConfigMap" {
			continue
		}
		if userData, ok := obj.Data["userData"]; ok {
			return userData
		}
	}
	t.Fatal("rendered chart has no ConfigMap carrying a userData key")
	return ""
}

// helmTemplate skips when helm is missing but fails under CI: the workflow installs helm,
// so a silent skip there would leave the chart's Ignition unasserted.
func helmTemplate(t *testing.T) string {
	t.Helper()

	helm, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("helm is not on PATH under CI: %v", err)
		}
		t.Skipf("helm is not on PATH: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	out, err := exec.CommandContext(ctx, helm, "template", "gateway-operator", chartDir(t), "--namespace", "wgnet-system").CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	return string(out)
}

func readChartFile(t *testing.T, relPath string) string {
	t.Helper()
	return readRepoFile(t, filepath.Join("k8s", "charts", "wireguard-gateway-operator", relPath))
}

func readRepoFile(t *testing.T, relPath string) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), relPath)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read repository file %s: %v", path, err)
	}
	return string(b)
}

func chartDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "k8s", "charts", "wireguard-gateway-operator")
}

// repoRoot resolves the repository root from this file's compile-time path, so
// paths held by the suite do not depend on the process working directory.
func repoRoot(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
}
