package link

import "fmt"

// MaxLinkID is the highest per-Gateway link id. The range is dense, so the lowest unused id is
// unique by construction; 250 keeps wg-gw250 inside the kernel's 15-character interface-name cap.
const MaxLinkID = 250

// healthPortBase is the base of the Local-mode loopback health-port range;
// healthPortBase+1..healthPortBase+MaxLinkID sits below the default NodePort range.
const healthPortBase = 27000

// markMaskBits masks the mark's high 16 bits, leaving the low 16 free so kube-proxy's
// 0x4000/0x8000 bits stay untouched by construction.
const markMaskBits uint32 = 0xffff0000

// markMask is markMaskBits as nftables and ip(8) spell it, the form the Identity carries.
// identity_test.go pins it against markMaskBits so the two cannot drift.
const markMask = "0xffff0000"

// routeTableBase is the base of the per-Gateway route-table range, clear of the
// reserved 253/254/255 tables.
const routeTableBase = 100000

// Identity is the set of node-global names and numbers a Local-mode link programs, all derived
// from the allocated link id. The operator derives them; the link treats them as given.
type Identity struct {
	ID         int    `json:"id"`
	Interface  string `json:"interface"`
	NftTable   string `json:"nftTable"`
	Mark       string `json:"mark"`
	MarkMask   string `json:"markMask"`
	RouteTable int    `json:"routeTable"`
	HealthPort int    `json:"healthPort"`
}

// NewIdentity derives the per-Gateway identity for a link id. The caller must pass an id in
// 1..MaxLinkID; the operator's allocator is the only caller, so NewIdentity does not re-check it.
func NewIdentity(id int) Identity {
	return Identity{
		ID:         id,
		Interface:  fmt.Sprintf("wg-gw%d", id),
		NftTable:   fmt.Sprintf("gw%d", id),
		Mark:       fmt.Sprintf("0x%08x", id<<16),
		MarkMask:   markMask,
		RouteTable: routeTableBase + id,
		HealthPort: healthPortBase + id,
	}
}
