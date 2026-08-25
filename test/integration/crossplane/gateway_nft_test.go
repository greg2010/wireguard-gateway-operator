package crossplane

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestGatewayNftAllowsIAPSSH asserts the shipped VM ruleset lets IAP-sourced SSH
// reach the local sshd. The prerouting chain DNATs every non-WireGuard port at
// eth0 to the link, so the accept must precede the DNAT rule: accept ends nat
// chain traversal, and a rule ordered after the DNAT is never reached.
func TestGatewayNftAllowsIAPSSH(t *testing.T) {
	prerouting := preroutingChain(t, readChartFile(t, filepath.Join("files", "gateway.nft")))

	acceptIdx := ruleIndex(prerouting, func(rule string) bool {
		return strings.Contains(rule, "ip saddr "+iapSourceRange) &&
			strings.Contains(rule, "tcp dport 22") &&
			strings.HasSuffix(rule, "accept")
	})
	if acceptIdx < 0 {
		t.Fatalf("prerouting chain has no accept rule for tcp/22 from %s:\n%s", iapSourceRange, strings.Join(prerouting, "\n"))
	}

	dnatIdx := ruleIndex(prerouting, func(rule string) bool {
		return strings.Contains(rule, "dnat ip to")
	})
	if dnatIdx < 0 {
		t.Fatalf("prerouting chain has no DNAT rule:\n%s", strings.Join(prerouting, "\n"))
	}

	if acceptIdx > dnatIdx {
		t.Errorf("IAP SSH accept is rule %d, after the DNAT rule %d; the DNAT would divert SSH before the accept is reached:\n%s",
			acceptIdx, dnatIdx, strings.Join(prerouting, "\n"))
	}
}

// preroutingChain returns the rule lines of the ruleset's prerouting chain in
// file order, excluding the chain declaration and its type/hook line.
func preroutingChain(t *testing.T, ruleset string) []string {
	t.Helper()

	var rules []string
	inChain := false
	for _, line := range strings.Split(ruleset, "\n") {
		rule := strings.TrimSpace(line)
		switch {
		case !inChain:
			if strings.HasPrefix(rule, "chain prerouting") {
				inChain = true
			}
		case rule == "}":
			return rules
		case rule == "" || strings.HasPrefix(rule, "type "):
		default:
			rules = append(rules, rule)
		}
	}
	if !inChain {
		t.Fatal("ruleset has no prerouting chain")
	}
	t.Fatal("prerouting chain is not closed")
	return nil
}

// ruleIndex returns the position of the first rule satisfying match, or -1.
func ruleIndex(rules []string, match func(string) bool) int {
	for i, rule := range rules {
		if match(rule) {
			return i
		}
	}
	return -1
}

// readChartFile reads a file at the given path relative to the operator chart
// directory, resolving it relative to this test file so it does not depend on
// the process working directory.
func readChartFile(t *testing.T, relPath string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	path := filepath.Join(repoRoot, "k8s", "charts", "wireguard-gateway-operator", relPath)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read chart file %s: %v", path, err)
	}
	return string(b)
}
