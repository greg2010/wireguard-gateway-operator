// Package responder renders the configuration of a Gateway's health responder, the nginx
// instance the cloud health check reaches through the link's DNAT.
package responder

import (
	_ "embed"
	"fmt"
)

// HealthPath is the request path the responder answers with 200.
const HealthPath = "/forwarded-healthz"

//go:embed nginx.conf.tmpl
var nginxConfText string

// NginxConf renders the nginx configuration a responder pod mounts: 200 on HealthPath,
// 404 elsewhere, temp paths under /tmp for a read-only root filesystem.
func NginxConf(port int32) string {
	return fmt.Sprintf(nginxConfText, port, HealthPath)
}
