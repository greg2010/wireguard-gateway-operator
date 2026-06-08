package e2e

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/greg2010/wireguard-gateway-operator/test/harness/k8s"
)

// operatorValues is the e2e overlay layered over the chart's values.yaml: it sets
// the run's images and pins nameOverride for a deterministic Deployment name. Every
// per-Gateway field lives on the Gateway CR, not here.
type operatorValues struct {
	NameOverride string        `yaml:"nameOverride"`
	Operator     operatorBlock `yaml:"operator"`
	Link         imageBlock    `yaml:"link"`
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

// valuesParams bundles the inputs that shape the operator overlay.
type valuesParams struct {
	nameOverride string
	// operatorImage and linkImage are the run's freshly built, kind-loaded images.
	operatorImage k8s.ImageRef
	linkImage     k8s.ImageRef
}

// writeValues renders the operator chart overlay for the single install and
// writes it to a temp file, returning the path. The caller passes the path to
// helm via -f.
func writeValues(dir string, p valuesParams) (string, error) {
	v := operatorValues{
		NameOverride: p.nameOverride,
		Operator: operatorBlock{
			Image: imageValues{Repository: p.operatorImage.Repository, Tag: p.operatorImage.Tag},
		},
		Link: imageBlock{
			Image: imageValues{Repository: p.linkImage.Repository, Tag: p.linkImage.Tag},
		},
	}

	data, err := yaml.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal operator values: %w", err)
	}
	path := filepath.Join(dir, p.nameOverride+"-values.yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("write operator values %s: %w", path, err)
	}
	return path, nil
}
