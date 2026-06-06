package e2e

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/greg2010/wireguard-gateway-operator/test/harness/k8s"
)

// operatorValues is the subset of the wireguard-gateway-operator chart values the
// e2e overlay sets. It is written to a temp file and passed to helm as -f,
// layered over the chart's own values.yaml. The chart installs the operator (not
// per-Gateway resources), so the overlay only sets the run's images, the GCP
// project, and a run-unique name prefix; every per-Gateway field (gcp region/zone,
// forwards, dnsHostnames) is expressed on the Gateway CR the suite creates, not
// here. WG params (incl. listenPort) keep their chart defaults.
type operatorValues struct {
	NameOverride string        `yaml:"nameOverride"`
	Operator     operatorBlock `yaml:"operator"`
	Link         imageBlock    `yaml:"link"`
	GCP          gcpValues     `yaml:"gcp"`
}

type operatorBlock struct {
	Image imageValues `yaml:"image"`
}

type imageBlock struct {
	Image imageValues `yaml:"image"`
}

type imageValues struct {
	Repository string `yaml:"repository"`
	Tag        string `yaml:"tag"`
}

type gcpValues struct {
	ProjectID string `yaml:"projectID"`
}

// valuesParams bundles the per-run inputs that shape the overlay.
type valuesParams struct {
	// namePrefix is the run-unique prefix threaded into nameOverride so the
	// operator's chart-rendered objects (Deployment, RBAC, ConfigMap) are named
	// per run and two concurrent runs never collide.
	namePrefix string
	env        Env
	// operatorImage and linkImage are the run's freshly built, kind-loaded images.
	operatorImage k8s.ImageRef
	linkImage     k8s.ImageRef
}

// writeValues renders the operator chart overlay for the run and writes it to a
// temp file, returning the path. The caller passes the path to helm via -f.
func writeValues(dir string, p valuesParams) (string, error) {
	v := operatorValues{
		NameOverride: p.namePrefix,
		Operator: operatorBlock{
			Image: imageValues{Repository: p.operatorImage.Repository, Tag: p.operatorImage.Tag},
		},
		Link: imageBlock{
			Image: imageValues{Repository: p.linkImage.Repository, Tag: p.linkImage.Tag},
		},
		GCP: gcpValues{ProjectID: p.env.ProjectID},
	}

	data, err := yaml.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal operator values: %w", err)
	}
	path := filepath.Join(dir, p.namePrefix+"-values.yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("write operator values %s: %w", path, err)
	}
	return path, nil
}
