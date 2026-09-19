package responder

import (
	"fmt"
	"strings"
	"testing"
)

func TestNginxConf(t *testing.T) {
	tests := []int32{27000, 8181}
	for _, port := range tests {
		t.Run(fmt.Sprintf("port=%d", port), func(t *testing.T) {
			conf := NginxConf(port)
			if !strings.HasPrefix(conf, "worker_processes 1;\n") {
				t.Errorf("NginxConf(%d) does not start with worker_processes directive: %q", port, conf)
			}
			if !strings.Contains(conf, fmt.Sprintf("listen %d;", port)) {
				t.Errorf("NginxConf(%d) missing listen directive", port)
			}
			if !strings.Contains(conf, "location = /forwarded-healthz {") {
				t.Errorf("NginxConf(%d) missing health path location block", port)
			}
			if !strings.HasSuffix(conf, "}\n") {
				t.Errorf("NginxConf(%d) does not end with closing brace: %q", port, conf)
			}
		})
	}
}
