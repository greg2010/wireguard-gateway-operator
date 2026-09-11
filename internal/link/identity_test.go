package link

import (
	"fmt"
	"testing"
)

func TestNewIdentity(t *testing.T) {
	tcs := []struct {
		name string
		id   int
		want Identity
	}{
		{
			name: "id=1",
			id:   1,
			want: Identity{1, "wg-gw1", "gw1", "0x00010000", "0xffff0000", 100001, 27001},
		},
		{
			name: "id=3",
			id:   3,
			want: Identity{3, "wg-gw3", "gw3", "0x00030000", "0xffff0000", 100003, 27003},
		},
		{
			name: "id=250",
			id:   250,
			want: Identity{250, "wg-gw250", "gw250", "0x00fa0000", "0xffff0000", 100250, 27250},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := NewIdentity(tc.id)
			if got != tc.want {
				t.Errorf("NewIdentity(%d) = %+v, want %+v", tc.id, got, tc.want)
			}
		})
	}
}

func TestNewIdentityInterfaceNameFitsIFNAMSIZ(t *testing.T) {
	const ifnamsizMinusOne = 15
	if got := len(NewIdentity(MaxLinkID).Interface); got > ifnamsizMinusOne {
		t.Errorf("len(NewIdentity(MaxLinkID).Interface) = %d, want <= %d", got, ifnamsizMinusOne)
	}
}

// TestMarkMaskMatchesBits pins the rendered mask against the bit constant the keep-mask
// is derived from, so the literal and the bits cannot drift apart.
func TestMarkMaskMatchesBits(t *testing.T) {
	if want := fmt.Sprintf("0x%08x", markMaskBits); markMask != want {
		t.Errorf("markMask = %q, want %q", markMask, want)
	}
}
