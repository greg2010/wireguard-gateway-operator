// Package config loads typed configuration from the process environment.
package config

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
)

// Load populates a value of type T from environment variables using its
// envconfig struct tags. The empty prefix means tags are read verbatim.
func Load[T any]() (T, error) {
	var cfg T
	if err := envconfig.Process("", &cfg); err != nil {
		return cfg, fmt.Errorf("process config: %w", err)
	}
	return cfg, nil
}
