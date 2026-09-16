package link

import (
	"fmt"
	"slices"
	"testing"
)

func TestNewGatewayIdentity(t *testing.T) {
	tcs := []struct {
		name string
		id   int
		want GatewayIdentity
	}{
		{name: "id=1", id: 1, want: GatewayIdentity{1, 27001, "gw1"}},
		{name: "id=3", id: 3, want: GatewayIdentity{3, 27003, "gw3"}},
		{name: "id=250", id: 250, want: GatewayIdentity{250, 27250, "gw250"}},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := NewGatewayIdentity(tc.id)
			if got != tc.want {
				t.Errorf("NewGatewayIdentity(%d) = %+v, want %+v", tc.id, got, tc.want)
			}
		})
	}
}

// TestSlotZeroIdentity pins the identity NewSlotIdentity derives for slot 0 of each gateway ID.
func TestSlotZeroIdentity(t *testing.T) {
	tcs := []struct {
		name string
		id   int
		want SlotIdentity
	}{
		{name: "id=1", id: 1, want: SlotIdentity{"wg-gw1", "0x00010000", "0xffff0000", 100001}},
		{name: "id=3", id: 3, want: SlotIdentity{"wg-gw3", "0x00030000", "0xffff0000", 100003}},
		{name: "id=250", id: 250, want: SlotIdentity{"wg-gw250", "0x00fa0000", "0xffff0000", 100250}},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := NewSlotIdentity(tc.id, 0)
			if got != tc.want {
				t.Errorf("NewSlotIdentity(%d, 0) = %+v, want %+v", tc.id, got, tc.want)
			}
		})
	}
}

func TestNewSlotIdentityNonZeroSlot(t *testing.T) {
	tcs := []struct {
		name string
		id   int
		slot int
		want SlotIdentity
	}{
		{name: "id=1_slot=2", id: 1, slot: 2, want: SlotIdentity{"wg-gw1-2", "0x02010000", "0xffff0000", 100513}},
		{name: "id=3_slot=1", id: 3, slot: 1, want: SlotIdentity{"wg-gw3-1", "0x01030000", "0xffff0000", 100259}},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := NewSlotIdentity(tc.id, tc.slot)
			if got != tc.want {
				t.Errorf("NewSlotIdentity(%d, %d) = %+v, want %+v", tc.id, tc.slot, got, tc.want)
			}
		})
	}
}

// TestExtremeSlotAndIDStayInBounds covers the highest valid gateway ID and slot.
func TestExtremeSlotAndIDStayInBounds(t *testing.T) {
	const ifnamsizMinusOne = 15
	got := NewSlotIdentity(MaxLinkID, 255)

	markBits, err := parseHexUint32(got.Mark)
	if err != nil {
		t.Fatalf("parse mark %q: %v", got.Mark, err)
	}
	if markBits&^markMaskBits != 0 {
		t.Errorf("mark = %q, has bits outside %#08x", got.Mark, markMaskBits)
	}
	if got.RouteTable < routeTableBase || got.RouteTable >= routeTableBase+(1<<16) {
		t.Errorf("route table = %d, want inside [%d, %d)", got.RouteTable, routeTableBase, routeTableBase+(1<<16))
	}
	if len(got.Interface) > ifnamsizMinusOne {
		t.Errorf("len(interface) = %d, want <= %d (interface %q)", len(got.Interface), ifnamsizMinusOne, got.Interface)
	}
}

func parseHexUint32(s string) (uint32, error) {
	var v uint32
	_, err := fmt.Sscanf(s, "0x%08x", &v)
	return v, err
}

func TestNewSlotIdentityInterfaceNameFitsIFNAMSIZ(t *testing.T) {
	const ifnamsizMinusOne = 15
	if got := len(NewSlotIdentity(MaxLinkID, 0).Interface); got > ifnamsizMinusOne {
		t.Errorf("len(NewSlotIdentity(MaxLinkID, 0).Interface) = %d, want <= %d", got, ifnamsizMinusOne)
	}
}

// TestMarkMaskMatchesBits pins the rendered mask against the bit constant the keep-mask
// is derived from, so the literal and the bits cannot drift apart.
func TestMarkMaskMatchesBits(t *testing.T) {
	if want := fmt.Sprintf("0x%08x", markMaskBits); markMask != want {
		t.Errorf("markMask = %q, want %q", markMask, want)
	}
}

// TestInheritedSlots covers discovery of this Gateway's current and departed slots.
func TestInheritedSlots(t *testing.T) {
	tcs := []struct {
		name      string
		names     []string
		gatewayID int
		want      []int
	}{
		{
			name:      "this_gateways_slots_among_another_gateways_interface",
			names:     []string{"lo", "eth0", "wg-gw3-2", "wg-gw4-2", "wg-gw3"},
			gatewayID: 3,
			want:      []int{0, 2},
		},
		{
			name:      "an_id_this_one_prefixes_is_another_gateway",
			names:     []string{"wg-gw30", "wg-gw30-1"},
			gatewayID: 3,
			want:      []int{},
		},
		{
			name:      "highest_slot_of_the_range",
			names:     []string{"wg-gw3-255"},
			gatewayID: 3,
			want:      []int{255},
		},
		{
			name:      "a_slot_past_the_range_is_not_this_gateways",
			names:     []string{"wg-gw3-256"},
			gatewayID: 3,
			want:      []int{},
		},
		{
			name:      "no_interface_of_this_gateway",
			names:     []string{"lo", "eth0"},
			gatewayID: 3,
			want:      []int{},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if got := InheritedSlots(tc.names, tc.gatewayID); !slices.Equal(got, tc.want) {
				t.Errorf("InheritedSlots(%v, %d) = %v, want %v", tc.names, tc.gatewayID, got, tc.want)
			}
		})
	}
}
