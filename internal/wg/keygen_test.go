package wg

import (
	"encoding/base64"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestGenerateKeypair(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	for _, tc := range []struct {
		name string
		key  string
	}{
		{name: "private", key: priv},
		{name: "public", key: pub},
	} {
		raw, err := base64.StdEncoding.DecodeString(tc.key)
		if err != nil {
			t.Errorf("%s key %q is not valid base64: %v", tc.name, tc.key, err)
			continue
		}
		if len(raw) != wgtypes.KeyLen {
			t.Errorf("%s key decodes to %d bytes, want %d", tc.name, len(raw), wgtypes.KeyLen)
		}
	}

	parsed, err := wgtypes.ParseKey(priv)
	if err != nil {
		t.Fatalf("ParseKey(private): %v", err)
	}
	if got := parsed.PublicKey().String(); got != pub {
		t.Errorf("public key %q is not derived from private key (re-derived %q)", pub, got)
	}
}

func TestGenerateKeypairDistinct(t *testing.T) {
	priv1, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (first): %v", err)
	}
	priv2, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (second): %v", err)
	}
	if priv1 == priv2 {
		t.Errorf("two calls produced identical private keys: %q", priv1)
	}
}
