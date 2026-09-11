package crossplane

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	// gatewayNftPath is the shipped VM ruleset, relative to the operator chart.
	gatewayNftPath = filepath.Join("files", "gcp", "gateway.nft")

	// keyfetchPath is the boot script that renders the ruleset, relative to the
	// operator chart.
	keyfetchPath = filepath.Join("files", "gcp", "keyfetch.sh")
)

// nftModes pairs each traffic policy with the postrouting verdict keyfetch.sh
// substitutes for it.
var nftModes = []struct {
	name    string
	policy  string
	verdict string
}{
	{name: "cluster", policy: "cluster", verdict: "masquerade"},
	{name: "local", policy: "local", verdict: "return"},
}

// nftTestValues stand in for the metadata attributes keyfetch.sh substitutes at boot.
// Every placeholder keyfetch.sh substitutes needs an entry here.
func nftTestValues(verdict string) map[string]string {
	return map[string]string{
		"__WG_LISTEN_PORT__":         "51820",
		"__WG_LINK_ADDRESS__":        "10.99.0.2",
		"__WG_POSTROUTING_VERDICT__": verdict,
	}
}

// verdictCase matches keyfetch.sh's postrouting_verdict case arm, so a change to the
// shipped mapping fails here rather than silently masquerading a Local gateway.
var verdictCase = regexp.MustCompile(`(?m)^\s*([a-z]+)\)\s*printf '%s' "([a-z]+)" ;;`)

// preroutingOrder lists rules in the order they must appear: the catch-all DNAT
// diverts every non-WireGuard port, so an accept placed after it is never reached.
var preroutingOrder = []struct {
	name  string
	match func(rule string) bool
}{
	{
		name: "IAP SSH accept",
		match: func(rule string) bool {
			return strings.HasPrefix(rule, `iif "eth0"`) &&
				strings.Contains(rule, "ip saddr "+iapSourceRange) &&
				strings.Contains(rule, "tcp dport 22") &&
				strings.HasSuffix(rule, "accept")
		},
	},
	{
		name: "catch-all DNAT to the link",
		match: func(rule string) bool {
			return strings.HasPrefix(rule, `iif "eth0"`) && strings.Contains(rule, "dnat ip to")
		},
	},
}

// TestGatewayNftRendersPerTrafficPolicy asserts Cluster masquerades tunnel egress and
// Local masquerades nothing. It reads the chart files, so it needs no container runtime.
func TestGatewayNftRendersPerTrafficPolicy(t *testing.T) {
	for _, mode := range nftModes {
		t.Run(mode.name, func(t *testing.T) {
			ruleset := renderGatewayNft(t, mode.verdict)
			assertPreroutingOrder(t, preroutingChain(t, ruleset))

			hasMasquerade := strings.Contains(ruleset, "masquerade")
			wantMasquerade := mode.verdict == "masquerade"
			if hasMasquerade != wantMasquerade {
				t.Errorf("traffic policy %s: ruleset contains masquerade = %t, want %t\n%s",
					mode.policy, hasMasquerade, wantMasquerade, ruleset)
			}
			want := `oifname "wg0" ` + mode.verdict
			if !strings.Contains(ruleset, want) {
				t.Errorf("traffic policy %s: ruleset missing %q\n%s", mode.policy, want, ruleset)
			}
		})
	}
}

// TestKeyfetchVerdictMapping asserts the shipped boot script and nftModes cannot drift
// apart on the policy-to-verdict mapping.
func TestKeyfetchVerdictMapping(t *testing.T) {
	matches := verdictCase.FindAllStringSubmatch(readChartFile(t, keyfetchPath), -1)
	got := make(map[string]string, len(matches))
	for _, m := range matches {
		got[m[1]] = m[2]
	}
	for _, mode := range nftModes {
		if mode.policy == "cluster" {
			// cluster is the fallback arm ("*)"), not a named case.
			continue
		}
		if got[mode.policy] != mode.verdict {
			t.Errorf("%s maps traffic policy %q to %q, want %q; the shipped mapping and nftModes have drifted",
				keyfetchPath, mode.policy, got[mode.policy], mode.verdict)
		}
	}
}

// assertPreroutingOrder checks every rule in preroutingOrder is present and that
// their positions increase in the listed order.
func assertPreroutingOrder(t *testing.T, prerouting []string) {
	t.Helper()

	prev, prevName := -1, ""
	for _, tc := range preroutingOrder {
		idx := ruleIndex(prerouting, tc.match)
		if idx < 0 {
			t.Fatalf("prerouting chain has no %s rule:\n%s", tc.name, strings.Join(prerouting, "\n"))
		}
		if idx <= prev {
			t.Errorf("prerouting %s is rule %d, not after %s at rule %d; the required order is %s then %s:\n%s",
				tc.name, idx, prevName, prev, prevName, tc.name, strings.Join(prerouting, "\n"))
		}
		prev, prevName = idx, tc.name
	}
}

// placeholderPattern matches the __NAME__ tokens keyfetch.sh substitutes.
var placeholderPattern = regexp.MustCompile(`__[A-Z0-9_]+__`)

// keyfetchSubstitution matches one `s|__NAME__|$value|g` expression of the sed
// invocation keyfetch.sh renders the ruleset with.
var keyfetchSubstitution = regexp.MustCompile(`s\|(__[A-Z0-9_]+__)\|[^|]*\|g`)

// renderGatewayNft yields the bytes the VM feeds to `nft -f`. It parses the
// placeholder list out of keyfetch.sh, so drift in either direction fails here.
func renderGatewayNft(t *testing.T, verdict string) string {
	t.Helper()

	raw := readChartFile(t, gatewayNftPath)

	values := nftTestValues(verdict)
	var pairs []string
	for _, placeholder := range keyfetchPlaceholders(t) {
		value, ok := values[placeholder]
		if !ok {
			t.Fatalf("%s substitutes %s, which has no test value in nftTestValues", keyfetchPath, placeholder)
		}
		if !strings.Contains(raw, placeholder) {
			t.Fatalf("%s substitutes %s, which %s does not contain", keyfetchPath, placeholder, gatewayNftPath)
		}
		pairs = append(pairs, placeholder, value)
	}

	ruleset := strings.NewReplacer(pairs...).Replace(raw)
	if left := placeholderPattern.FindAllString(ruleset, -1); len(left) > 0 {
		t.Fatalf("no parsed substitution of %s covers %s placeholders %v; check the sed form in %s's render_nft",
			keyfetchPath, gatewayNftPath, left, keyfetchPath)
	}
	return ruleset
}

// keyfetchPlaceholders returns the placeholder names keyfetch.sh's sed invocation
// replaces, in file order.
func keyfetchPlaceholders(t *testing.T) []string {
	t.Helper()

	matches := keyfetchSubstitution.FindAllStringSubmatch(readChartFile(t, keyfetchPath), -1)
	if len(matches) == 0 {
		t.Fatalf("%s has no `s|__NAME__|...|g` substitutions; the ruleset would boot unrendered", keyfetchPath)
	}

	placeholders := make([]string, 0, len(matches))
	for _, m := range matches {
		placeholders = append(placeholders, m[1])
	}
	return placeholders
}

// preroutingChain returns the rule lines of the ruleset's prerouting chain in
// file order, excluding the chain declaration and its type/hook line.
func preroutingChain(t *testing.T, ruleset string) []string {
	t.Helper()

	var rules []string
	inChain := false
	for line := range strings.SplitSeq(ruleset, "\n") {
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
