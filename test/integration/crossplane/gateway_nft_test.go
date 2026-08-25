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

// nftTestValues stand in for the metadata attributes keyfetch.sh substitutes into
// the ruleset at instance boot, keyed by placeholder. Every placeholder keyfetch.sh
// substitutes needs an entry here.
var nftTestValues = map[string]string{
	"__WG_LISTEN_PORT__":  "51820",
	"__WG_LINK_ADDRESS__": "10.99.0.2",
}

// preroutingOrder lists the prerouting rules whose relative order the gateway
// ruleset depends on, in the order they must appear. The DNAT diverts every
// non-WireGuard port at eth0 to the link, so an accept placed after it is never
// reached: accept ends nat chain traversal.
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

// TestGatewayNftAllowsIAPSSH asserts the shipped VM ruleset lets IAP-sourced SSH
// reach the local sshd. It reads the chart file directly, so it runs without a
// container runtime and catches an ordering regression even where the loading
// test cannot run.
func TestGatewayNftAllowsIAPSSH(t *testing.T) {
	assertPreroutingOrder(t, preroutingChain(t, renderGatewayNft(t)))
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

// renderGatewayNft yields the bytes the VM feeds to `nft -f`, substituting exactly
// the placeholders keyfetch.sh substitutes rather than a hand-kept copy of that
// list: a sed expression dropped from keyfetch.sh's render_nft must fail here, not
// brick a booting gateway. It fails if the two files have drifted in either direction.
func renderGatewayNft(t *testing.T) string {
	t.Helper()

	raw := readChartFile(t, gatewayNftPath)

	var pairs []string
	for _, placeholder := range keyfetchPlaceholders(t) {
		value, ok := nftTestValues[placeholder]
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
