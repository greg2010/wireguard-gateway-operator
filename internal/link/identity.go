package link

import (
	"fmt"
	"slices"
)

// MaxLinkID is the highest per-Gateway link id. The range is dense, so the lowest unused id is
// unique by construction; 250 keeps wg-gw250 inside the kernel's 15-character interface-name cap.
const MaxLinkID = 250

// healthPortBase is the base of the Local-mode loopback health-port range;
// healthPortBase+1..healthPortBase+MaxLinkID sits below the default NodePort range.
const healthPortBase = 27000

// markMaskBits masks the mark's high 16 bits, leaving the low 16 free so kube-proxy's
// 0x4000/0x8000 bits stay untouched by construction.
const markMaskBits uint32 = 0xffff0000

// markMask is markMaskBits as nftables and ip(8) spell it, the form SlotIdentity carries.
// identity_test.go pins it against markMaskBits so the two cannot drift.
const markMask = "0xffff0000"

// routeTableBase is the base of the per-Gateway route-table range, clear of the
// reserved 253/254/255 tables.
const routeTableBase = 100000

// slotCount is the size of the slot range a Gateway's routing key reserves: the key's second byte
// is the slot, so 0..255 covers every interface name the Gateway can own.
const slotCount = 256

// GatewayIdentity is the Gateway-level constant set a Local-mode link programs, unchanged by
// slot: the operator derives it, the link treats it as given.
type GatewayIdentity struct {
	ID         int    `json:"id"`
	HealthPort int    `json:"healthPort"`
	NftTable   string `json:"nftTable"`
}

// NewGatewayIdentity derives the Gateway-level identity for a link id. The caller must pass an id
// in 1..MaxLinkID; the operator's allocator is the only caller, so this does not re-check it.
func NewGatewayIdentity(id int) GatewayIdentity {
	return GatewayIdentity{
		ID:         id,
		HealthPort: healthPortBase + id,
		NftTable:   fmt.Sprintf("gw%d", id),
	}
}

// SlotIdentity is one slot's node-global names and numbers, derived purely from
// (gatewayID, slot), never persisted redundantly into the RuntimeConfig JSON.
type SlotIdentity struct {
	Interface  string
	Mark       string
	MarkMask   string
	RouteTable int
}

// NewSlotIdentity derives slot's identity within gatewayID: k = (slot<<8)|gatewayID; mark
// k<<16; route table 100000+k; interface wg-gw<gatewayID>[-<slot>], slot 0 keeping the bare
// wg-gw<gatewayID> (its k is gatewayID itself).
func NewSlotIdentity(gatewayID, slot int) SlotIdentity {
	k := (slot << 8) | gatewayID
	iface := fmt.Sprintf("wg-gw%d", gatewayID)
	if slot != 0 {
		iface = fmt.Sprintf("wg-gw%d-%d", gatewayID, slot)
	}
	return SlotIdentity{
		Interface:  iface,
		Mark:       fmt.Sprintf("0x%08x", k<<16),
		MarkMask:   markMask,
		RouteTable: routeTableBase + k,
	}
}

// InheritedSlots returns, sorted, the slots of gatewayID whose interface is among names. names is
// one enumeration of the node's links, so an interface a crashed holder left behind is found even
// for a slot the current config no longer lists. Exported so an out-of-process harness runs the
// product's own discovery.
func InheritedSlots(names []string, gatewayID int) []int {
	owned := make(map[string]int, slotCount)
	for slot := range slotCount {
		owned[NewSlotIdentity(gatewayID, slot).Interface] = slot
	}
	slots := []int{}
	for _, name := range names {
		if slot, ok := owned[name]; ok {
			slots = append(slots, slot)
		}
	}
	slices.Sort(slots)
	return slots
}
