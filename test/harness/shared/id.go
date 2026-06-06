package shared

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
)

// ShortID returns a short, lowercase, DNS-label-safe random identifier (8 hex
// chars). Used to make per-run resource names unique so concurrent or leftover
// runs do not collide.
func ShortID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// dnsLabelDisallowed matches any run of characters not allowed in a DNS-1123
// label (lowercase alphanumerics and hyphen).
var dnsLabelDisallowed = regexp.MustCompile(`[^a-z0-9-]+`)

// Slug normalizes s into a DNS-1123-label-safe token: lowercased, with
// disallowed characters collapsed to single hyphens and the result trimmed of
// leading/trailing hyphens. Used to derive resource names from test names.
func Slug(s string) string {
	s = strings.ToLower(s)
	s = dnsLabelDisallowed.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}
