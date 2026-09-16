// Package gcpdiscovery reads the membership of a load-balanced Gateway's regional managed
// instance group from the Compute Engine API. It issues no write: every method is a read-only
// snapshot pass.
package gcpdiscovery

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"cloud.google.com/go/auth/credentials"
	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/option"
)

// MemberAction is the regionInstanceGroupManagers.listManagedInstances currentAction enum,
// verbatim.
type MemberAction string

const (
	ActionNone                   MemberAction = "NONE"
	ActionCreating               MemberAction = "CREATING"
	ActionCreatingWithoutRetries MemberAction = "CREATING_WITHOUT_RETRIES"
	ActionRecreating             MemberAction = "RECREATING"
	ActionDeleting               MemberAction = "DELETING"
	ActionAbandoning             MemberAction = "ABANDONING"
	ActionRestarting             MemberAction = "RESTARTING"
	ActionRefreshing             MemberAction = "REFRESHING"
	ActionVerifying              MemberAction = "VERIFYING"
)

// Verdict is the classification table's outcome for one listed entry.
type Verdict int

const (
	VerdictDeparted Verdict = iota // DELETING or ABANDONING: never a detail read
	VerdictPending                 // no id, no record: never a detail read
	VerdictPresent                 // has id, or has a record: detail read only under a trigger
)

// Classify evaluates the classification table in its own order. hasRecord is the caller's
// durable-record lookup; it turns an id-less listed name into VerdictPresent instead of
// VerdictPending.
func Classify(action MemberAction, hasInstanceID, hasRecord bool) Verdict {
	switch action {
	case ActionDeleting, ActionAbandoning:
		return VerdictDeparted
	case ActionRecreating:
		return VerdictPresent
	case ActionNone, ActionCreating, ActionCreatingWithoutRetries, ActionRestarting, ActionRefreshing, ActionVerifying:
	}
	if !hasInstanceID {
		if hasRecord {
			return VerdictPresent
		}
		return VerdictPending
	}
	return VerdictPresent
}

// ListedMember is one entry of a listManagedInstances page.
type ListedMember struct {
	Name             string
	Action           MemberAction
	InstanceID       string // "" when the instance does not exist yet
	Verdict          Verdict
	Zone             string // parsed from the listed instance URL
	TemplateRevision string // last path segment of version.instanceTemplate; "" for DELETING/ABANDONING
}

// DetailReason names which trigger issued a detail read.
type DetailReason string

const (
	DetailReasonNoRecordedAddress DetailReason = "no-recorded-address"
	DetailReasonIDChanged         DetailReason = "id-changed"
	DetailReasonPeriodicRefresh   DetailReason = "periodic-refresh"
)

// Detail is one instances.get result, issued only under a DetailReason.
type Detail struct {
	Name            string
	InstanceID      string
	ExternalAddress string
	Reason          DetailReason
}

// Recorded is the caller's prior knowledge of one name, used by List to decide triggers 1
// and 2.
type Recorded struct {
	Name            string
	ExternalAddress string // "" means "no recorded address" (trigger 1)
	InstanceID      string // compared against the listed id for trigger 2
}

// Snapshot is one usable pass: every listed member plus every detail this pass actually read,
// keyed by name. A Client never returns a partial Snapshot.
type Snapshot struct {
	Members []ListedMember
	Details map[string]Detail
}

// Client is the discovery seam. One List call is one usable-or-none pass: an error means no
// snapshot, never a partial one. Implementations issue no cloud write.
type Client interface {
	// List fetches every managed instance and authorized details; it returns no partial snapshot.
	List(ctx context.Context, project, region, mig string, recorded []Recorded, refreshNames []string) (Snapshot, error)
}

// NewClient builds a Client wrapping cloud.google.com/go/compute/apiv1. credentialJSON is the
// raw service-account key; empty selects the ambient credential chain (option.WithoutAuthentication
// is never used — an empty credential means google.FindDefaultCredentials, not anonymous access).
func NewClient(ctx context.Context, credentialJSON []byte) (Client, error) {
	var opts []option.ClientOption
	if len(credentialJSON) > 0 {
		creds, err := credentials.NewCredentialsFromJSON(credentials.ServiceAccount, credentialJSON, &credentials.DetectOptions{
			Scopes: compute.DefaultAuthScopes(),
		})
		if err != nil {
			return nil, fmt.Errorf("gcp credentials: %w", err)
		}
		opts = append(opts, option.WithAuthCredentials(creds))
	}
	return newClient(ctx, opts...)
}

// restClient is the real Client implementation, built by NewClient and, with a controlled
// endpoint, by the tests in client_test.go.
type restClient struct {
	igm  *compute.RegionInstanceGroupManagersClient
	inst *compute.InstancesClient
}

func newClient(ctx context.Context, opts ...option.ClientOption) (Client, error) {
	igm, err := compute.NewRegionInstanceGroupManagersRESTClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("building region instance group managers client: %w", err)
	}
	inst, err := compute.NewInstancesRESTClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("building instances client: %w", err)
	}
	return &restClient{igm: igm, inst: inst}, nil
}

// detailFetch is one instances.get this pass must issue, resolved while walking the listing.
type detailFetch struct {
	name     string
	zone     string
	listedID string // always non-empty: an id-less entry triggers no fetch
	reason   DetailReason
}

func (c *restClient) List(ctx context.Context, project, region, mig string, recorded []Recorded, refreshNames []string) (Snapshot, error) {
	recordedByName := make(map[string]Recorded, len(recorded))
	for _, r := range recorded {
		recordedByName[r.Name] = r
	}
	refreshSet := make(map[string]struct{}, len(refreshNames))
	for _, name := range refreshNames {
		refreshSet[name] = struct{}{}
	}

	it := c.igm.ListManagedInstances(ctx, &computepb.ListManagedInstancesRegionInstanceGroupManagersRequest{
		Project:              project,
		Region:               region,
		InstanceGroupManager: mig,
	})

	var members []ListedMember
	var fetches []detailFetch
	for mi, err := range it.All() {
		if err != nil {
			return Snapshot{}, fmt.Errorf("listing managed instances for %s/%s/%s: %w", project, region, mig, err)
		}

		name := mi.GetName()
		action := MemberAction(mi.GetCurrentAction())
		var instanceID string
		if mi.Id != nil {
			instanceID = strconv.FormatUint(mi.GetId(), 10)
		}
		rec, hasRecord := recordedByName[name]
		verdict := Classify(action, instanceID != "", hasRecord)
		members = append(members, ListedMember{
			Name:             name,
			Action:           action,
			InstanceID:       instanceID,
			Verdict:          verdict,
			Zone:             zoneFromInstanceURL(mi.GetInstance()),
			TemplateRevision: templateRevision(mi.GetVersion().GetInstanceTemplate()),
		})

		// Recreating and ID-less entries retain their records without a detail read.
		if verdict != VerdictPresent || action == ActionRecreating || instanceID == "" {
			continue
		}
		_, wantsRefresh := refreshSet[name]
		switch {
		case hasRecord && rec.ExternalAddress == "":
			fetches = append(fetches, detailFetch{name: name, zone: zoneFromInstanceURL(mi.GetInstance()), listedID: instanceID, reason: DetailReasonNoRecordedAddress})
		case instanceID != rec.InstanceID:
			fetches = append(fetches, detailFetch{name: name, zone: zoneFromInstanceURL(mi.GetInstance()), listedID: instanceID, reason: DetailReasonIDChanged})
		case wantsRefresh:
			fetches = append(fetches, detailFetch{name: name, zone: zoneFromInstanceURL(mi.GetInstance()), listedID: instanceID, reason: DetailReasonPeriodicRefresh})
		}
	}

	details := make(map[string]Detail, len(fetches))
	for _, f := range fetches {
		inst, err := c.inst.Get(ctx, &computepb.GetInstanceRequest{Project: project, Zone: f.zone, Instance: f.name})
		if err != nil {
			return Snapshot{}, fmt.Errorf("reading instance detail for %s: %w", f.name, err)
		}
		gotID := strconv.FormatUint(inst.GetId(), 10)
		if gotID != f.listedID {
			return Snapshot{}, fmt.Errorf("instance detail for %s: id mismatch, listed %s got %s", f.name, f.listedID, gotID)
		}
		details[f.name] = Detail{
			Name:            f.name,
			InstanceID:      gotID,
			ExternalAddress: externalAddress(inst),
			Reason:          f.reason,
		}
	}

	return Snapshot{Members: members, Details: details}, nil
}

// zoneFromInstanceURL extracts the zone segment from a Compute instance self-link. The URL can
// exist even before the instance is created, so it is the only source of an unlisted zone.
func zoneFromInstanceURL(url string) string {
	segments := strings.Split(url, "/")
	for i, segment := range segments {
		if segment == "zones" && i+1 < len(segments) {
			return segments[i+1]
		}
	}
	return ""
}

// templateRevision returns the last path segment of an instanceTemplate URL, or "" when url is
// empty, as for DELETING/ABANDONING entries.
func templateRevision(url string) string {
	if url == "" {
		return ""
	}
	segments := strings.Split(url, "/")
	return segments[len(segments)-1]
}

func externalAddress(inst *computepb.Instance) string {
	for _, ni := range inst.GetNetworkInterfaces() {
		for _, ac := range ni.GetAccessConfigs() {
			if ac.GetNatIP() != "" {
				return ac.GetNatIP()
			}
		}
	}
	return ""
}
