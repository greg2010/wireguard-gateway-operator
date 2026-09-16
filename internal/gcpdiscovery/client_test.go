package gcpdiscovery

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"google.golang.org/api/option"
)

// pageFixture is one listManagedInstances response, keyed by the pageToken that requests it
// ("" for the first page).
type pageFixture struct {
	status int
	body   string
}

// detailFixture is one instances.get response for a single instance name.
type detailFixture struct {
	status int
	body   string
}

// fixtureServer is the controlled in-process HTTP endpoint client_test.go drives the real
// adapter against, never a mock of the generated wire client.
type fixtureServer struct {
	t       *testing.T
	mu      sync.Mutex
	pages   map[string]pageFixture
	details map[string]detailFixture
	calls   []string
}

func newFixtureServer(t *testing.T) *fixtureServer {
	t.Helper()
	return &fixtureServer{t: t, pages: map[string]pageFixture{}, details: map[string]detailFixture{}}
}

func (f *fixtureServer) start() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(f.handle))
}

func (f *fixtureServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+strings.TrimSuffix(r.URL.Path, "/"))
	f.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/listManagedInstances"):
		token := r.URL.Query().Get("pageToken")
		f.mu.Lock()
		page, ok := f.pages[token]
		f.mu.Unlock()
		if !ok {
			f.t.Fatalf("unexpected listManagedInstances page token %q", token)
		}
		writeJSON(f.t, w, page.status, page.body)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/instances/"):
		name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		f.mu.Lock()
		d, ok := f.details[name]
		f.mu.Unlock()
		if !ok {
			f.t.Fatalf("unexpected instances.get for %q", name)
		}
		writeJSON(f.t, w, d.status, d.body)
	default:
		f.t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, body string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// t.Errorf, never t.Fatalf: this runs on the server's goroutine, not the test's.
	if _, err := w.Write([]byte(body)); err != nil {
		t.Errorf("write fixture response: %v", err)
	}
}

func (f *fixtureServer) sortedCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]string(nil), f.calls...)
	sort.Strings(out)
	return out
}

// newTestClient builds a Client against srv's URL with no authentication, mirroring what
// NewClient does for a real endpoint but pointed at the fixture server.
func newTestClient(t *testing.T, srv *httptest.Server) Client {
	t.Helper()
	c, err := newClient(context.Background(), option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	return c
}

// managedInstanceJSON omits absent ID and template fields as the Compute API does.
func managedInstanceJSON(name, action, id, instanceURL, templateURL string) string {
	fields := []string{
		`"name":"` + name + `"`,
		`"currentAction":"` + action + `"`,
	}
	if id != "" {
		fields = append(fields, `"id":"`+id+`"`)
	}
	if instanceURL != "" {
		fields = append(fields, `"instance":"`+instanceURL+`"`)
	}
	if templateURL != "" {
		fields = append(fields, `"version":{"instanceTemplate":"`+templateURL+`"}`)
	}
	return "{" + strings.Join(fields, ",") + "}"
}

func instanceURL(project, zone, name string) string {
	return "https://www.googleapis.com/compute/v1/projects/" + project + "/zones/" + zone + "/instances/" + name
}

func templateURL(project, revision string) string {
	return "https://www.googleapis.com/compute/v1/projects/" + project + "/global/instanceTemplates/" + revision
}

func instanceDetailJSON(id, name, natIP string) string {
	if natIP == "" {
		return `{"id":"` + id + `","name":"` + name + `"}`
	}
	return `{"id":"` + id + `","name":"` + name + `","networkInterfaces":[{"accessConfigs":[{"natIP":"` + natIP + `"}]}]}`
}

const project = "proj"
const region = "us-central1"
const mig = "gw-mig"
const zone = "us-central1-a"
const revision = "tmpl-1"

func TestList(t *testing.T) {
	t.Run("multi_page_listing_yields_every_member", func(t *testing.T) {
		srv := newFixtureServer(t)
		srv.pages[""] = pageFixture{status: 200, body: `{"managedInstances":[` +
			managedInstanceJSON("gw-0", "NONE", "1", instanceURL(project, zone, "gw-0"), templateURL(project, revision)) + `],"nextPageToken":"tok2"}`}
		srv.pages["tok2"] = pageFixture{status: 200, body: `{"managedInstances":[` +
			managedInstanceJSON("gw-1", "NONE", "2", instanceURL(project, zone, "gw-1"), templateURL(project, revision)) + `]}`}
		s := srv.start()
		defer s.Close()

		snap, err := newTestClient(t, s).List(context.Background(), project, region, mig,
			[]Recorded{
				{Name: "gw-0", ExternalAddress: "1.1.1.1", InstanceID: "1"},
				{Name: "gw-1", ExternalAddress: "2.2.2.2", InstanceID: "2"},
			}, nil)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		want := []ListedMember{
			{Name: "gw-0", Action: ActionNone, InstanceID: "1", Verdict: VerdictPresent, Zone: zone, TemplateRevision: revision},
			{Name: "gw-1", Action: ActionNone, InstanceID: "2", Verdict: VerdictPresent, Zone: zone, TemplateRevision: revision},
		}
		assertMembers(t, snap.Members, want)
	})

	t.Run("id_less_member_with_no_record_is_pending", func(t *testing.T) {
		srv := newFixtureServer(t)
		srv.pages[""] = pageFixture{status: 200, body: `{"managedInstances":[` +
			managedInstanceJSON("gw-0", "CREATING", "", instanceURL(project, zone, "gw-0"), templateURL(project, revision)) + `]}`}
		s := srv.start()
		defer s.Close()

		snap, err := newTestClient(t, s).List(context.Background(), project, region, mig, nil, nil)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		want := []ListedMember{{Name: "gw-0", Action: ActionCreating, InstanceID: "", Verdict: VerdictPending, Zone: zone, TemplateRevision: revision}}
		assertMembers(t, snap.Members, want)
		assertDetails(t, snap.Details, map[string]Detail{})
		assertCalls(t, srv, []string{"POST /compute/v1/projects/proj/regions/us-central1/instanceGroupManagers/gw-mig/listManagedInstances"})
	})

	t.Run("id_less_member_with_record_is_present", func(t *testing.T) {
		srv := newFixtureServer(t)
		srv.pages[""] = pageFixture{status: 200, body: `{"managedInstances":[` +
			managedInstanceJSON("gw-0", "CREATING", "", instanceURL(project, zone, "gw-0"), templateURL(project, revision)) + `]}`}
		s := srv.start()
		defer s.Close()

		snap, err := newTestClient(t, s).List(context.Background(), project, region, mig,
			[]Recorded{{Name: "gw-0", ExternalAddress: "1.1.1.1", InstanceID: ""}}, nil)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		want := []ListedMember{{Name: "gw-0", Action: ActionCreating, InstanceID: "", Verdict: VerdictPresent, Zone: zone, TemplateRevision: revision}}
		assertMembers(t, snap.Members, want)
		assertDetails(t, snap.Details, map[string]Detail{})
		assertCalls(t, srv, []string{"POST /compute/v1/projects/proj/regions/us-central1/instanceGroupManagers/gw-mig/listManagedInstances"})
	})

	t.Run("pagination_error_yields_no_snapshot", func(t *testing.T) {
		srv := newFixtureServer(t)
		srv.pages[""] = pageFixture{status: 200, body: `{"managedInstances":[` +
			managedInstanceJSON("gw-0", "NONE", "1", instanceURL(project, zone, "gw-0"), templateURL(project, revision)) + `],"nextPageToken":"tok2"}`}
		srv.pages["tok2"] = pageFixture{status: 500, body: `{"error":{"code":500,"message":"boom"}}`}
		s := srv.start()
		defer s.Close()

		snap, err := newTestClient(t, s).List(context.Background(), project, region, mig, nil, nil)
		if err == nil {
			t.Fatalf("List: want error, got nil")
		}
		assertMembers(t, snap.Members, []ListedMember{})
		assertDetails(t, snap.Details, map[string]Detail{})
	})

	t.Run("no_recorded_address_reads_the_detail", func(t *testing.T) {
		srv := newFixtureServer(t)
		srv.pages[""] = pageFixture{status: 200, body: `{"managedInstances":[` +
			managedInstanceJSON("gw-0", "NONE", "1", instanceURL(project, zone, "gw-0"), templateURL(project, revision)) + `]}`}
		srv.details["gw-0"] = detailFixture{status: 200, body: instanceDetailJSON("1", "gw-0", "9.9.9.9")}
		s := srv.start()
		defer s.Close()

		snap, err := newTestClient(t, s).List(context.Background(), project, region, mig,
			[]Recorded{{Name: "gw-0", ExternalAddress: "", InstanceID: "1"}}, nil)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(snap.Details) != 1 {
			t.Fatalf("Details = %v, want exactly one entry", snap.Details)
		}
		want := Detail{Name: "gw-0", InstanceID: "1", ExternalAddress: "9.9.9.9", Reason: DetailReasonNoRecordedAddress}
		if snap.Details["gw-0"] != want {
			t.Fatalf("Details[gw-0] = %+v, want %+v", snap.Details["gw-0"], want)
		}
		assertCalls(t, srv, []string{
			"POST /compute/v1/projects/proj/regions/us-central1/instanceGroupManagers/gw-mig/listManagedInstances",
			"GET /compute/v1/projects/proj/zones/us-central1-a/instances/gw-0",
		})
	})

	t.Run("changed_id_reads_the_detail", func(t *testing.T) {
		srv := newFixtureServer(t)
		srv.pages[""] = pageFixture{status: 200, body: `{"managedInstances":[` +
			managedInstanceJSON("gw-0", "NONE", "789", instanceURL(project, zone, "gw-0"), templateURL(project, revision)) + `]}`}
		srv.details["gw-0"] = detailFixture{status: 200, body: instanceDetailJSON("789", "gw-0", "9.9.9.9")}
		s := srv.start()
		defer s.Close()

		snap, err := newTestClient(t, s).List(context.Background(), project, region, mig,
			[]Recorded{{Name: "gw-0", ExternalAddress: "1.1.1.1", InstanceID: "123"}}, nil)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(snap.Details) != 1 {
			t.Fatalf("Details = %v, want exactly one entry", snap.Details)
		}
		if snap.Details["gw-0"].Reason != DetailReasonIDChanged {
			t.Fatalf("Details[gw-0].Reason = %v, want %v", snap.Details["gw-0"].Reason, DetailReasonIDChanged)
		}
	})

	t.Run("empty_listed_id_reads_no_detail", func(t *testing.T) {
		srv := newFixtureServer(t)
		srv.pages[""] = pageFixture{status: 200, body: `{"managedInstances":[` +
			managedInstanceJSON("gw-0", "CREATING", "", instanceURL(project, zone, "gw-0"), templateURL(project, revision)) + `]}`}
		s := srv.start()
		defer s.Close()

		snap, err := newTestClient(t, s).List(context.Background(), project, region, mig,
			[]Recorded{{Name: "gw-0", ExternalAddress: "1.1.1.1", InstanceID: "123"}}, nil)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		assertDetails(t, snap.Details, map[string]Detail{})
		assertCalls(t, srv, []string{"POST /compute/v1/projects/proj/regions/us-central1/instanceGroupManagers/gw-mig/listManagedInstances"})
	})

	t.Run("recreating_member_reads_no_detail", func(t *testing.T) {
		const listing = "POST /compute/v1/projects/proj/regions/us-central1/instanceGroupManagers/gw-mig/listManagedInstances"
		const detailRead = "GET /compute/v1/projects/proj/zones/us-central1-a/instances/gw-0"
		tests := []struct {
			name        string
			action      string
			wantAction  MemberAction
			wantDetails map[string]Detail
			wantCalls   []string
		}{
			{
				name: "recreating", action: "RECREATING", wantAction: ActionRecreating,
				wantDetails: map[string]Detail{},
				wantCalls:   []string{listing},
			},
			{
				name: "present", action: "NONE", wantAction: ActionNone,
				wantDetails: map[string]Detail{
					"gw-0": {Name: "gw-0", InstanceID: "789", ExternalAddress: "9.9.9.9", Reason: DetailReasonNoRecordedAddress},
				},
				wantCalls: []string{listing, detailRead},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				srv := newFixtureServer(t)
				srv.pages[""] = pageFixture{status: 200, body: `{"managedInstances":[` +
					managedInstanceJSON("gw-0", tt.action, "789", instanceURL(project, zone, "gw-0"), templateURL(project, revision)) + `]}`}
				srv.details["gw-0"] = detailFixture{status: 200, body: instanceDetailJSON("789", "gw-0", "9.9.9.9")}
				s := srv.start()
				defer s.Close()

				snap, err := newTestClient(t, s).List(context.Background(), project, region, mig,
					[]Recorded{{Name: "gw-0", ExternalAddress: "", InstanceID: "123"}}, []string{"gw-0"})
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				assertMembers(t, snap.Members, []ListedMember{{
					Name: "gw-0", Action: tt.wantAction, InstanceID: "789", Verdict: VerdictPresent,
					Zone: zone, TemplateRevision: revision,
				}})
				assertDetails(t, snap.Details, tt.wantDetails)
				assertCalls(t, srv, tt.wantCalls)
			})
		}
	})

	t.Run("id_less_member_keeps_its_record_and_reads_no_detail", func(t *testing.T) {
		const listing = "POST /compute/v1/projects/proj/regions/us-central1/instanceGroupManagers/gw-mig/listManagedInstances"
		const detailRead = "GET /compute/v1/projects/proj/zones/us-central1-a/instances/gw-0"
		tests := []struct {
			name        string
			listedID    string
			wantDetails map[string]Detail
			wantCalls   []string
		}{
			{
				name: "empty listed id", listedID: "",
				wantDetails: map[string]Detail{},
				wantCalls:   []string{listing},
			},
			{
				name: "listed id", listedID: "789",
				wantDetails: map[string]Detail{
					"gw-0": {Name: "gw-0", InstanceID: "789", ExternalAddress: "9.9.9.9", Reason: DetailReasonNoRecordedAddress},
				},
				wantCalls: []string{listing, detailRead},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				srv := newFixtureServer(t)
				srv.pages[""] = pageFixture{status: 200, body: `{"managedInstances":[` +
					managedInstanceJSON("gw-0", "CREATING", tt.listedID, instanceURL(project, zone, "gw-0"), templateURL(project, revision)) + `]}`}
				srv.details["gw-0"] = detailFixture{status: 200, body: instanceDetailJSON("789", "gw-0", "9.9.9.9")}
				s := srv.start()
				defer s.Close()

				snap, err := newTestClient(t, s).List(context.Background(), project, region, mig,
					[]Recorded{{Name: "gw-0", ExternalAddress: "", InstanceID: "123"}}, []string{"gw-0"})
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				assertMembers(t, snap.Members, []ListedMember{{
					Name: "gw-0", Action: ActionCreating, InstanceID: tt.listedID, Verdict: VerdictPresent,
					Zone: zone, TemplateRevision: revision,
				}})
				assertDetails(t, snap.Details, tt.wantDetails)
				assertCalls(t, srv, tt.wantCalls)
			})
		}
	})

	t.Run("periodic_refresh_reads_the_detail", func(t *testing.T) {
		srv := newFixtureServer(t)
		srv.pages[""] = pageFixture{status: 200, body: `{"managedInstances":[` +
			managedInstanceJSON("gw-0", "NONE", "1", instanceURL(project, zone, "gw-0"), templateURL(project, revision)) + `]}`}
		srv.details["gw-0"] = detailFixture{status: 200, body: instanceDetailJSON("1", "gw-0", "9.9.9.9")}
		s := srv.start()
		defer s.Close()

		snap, err := newTestClient(t, s).List(context.Background(), project, region, mig,
			[]Recorded{{Name: "gw-0", ExternalAddress: "1.1.1.1", InstanceID: "1"}}, []string{"gw-0"})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(snap.Details) != 1 {
			t.Fatalf("Details = %v, want exactly one entry", snap.Details)
		}
		if snap.Details["gw-0"].Reason != DetailReasonPeriodicRefresh {
			t.Fatalf("Details[gw-0].Reason = %v, want %v", snap.Details["gw-0"].Reason, DetailReasonPeriodicRefresh)
		}
	})

	t.Run("detail_read_notfound_fails_whole_pass", func(t *testing.T) {
		srv := newFixtureServer(t)
		srv.pages[""] = pageFixture{status: 200, body: `{"managedInstances":[` +
			managedInstanceJSON("gw-0", "NONE", "1", instanceURL(project, zone, "gw-0"), templateURL(project, revision)) + `]}`}
		srv.details["gw-0"] = detailFixture{status: 404, body: `{"error":{"code":404,"message":"not found"}}`}
		s := srv.start()
		defer s.Close()

		snap, err := newTestClient(t, s).List(context.Background(), project, region, mig,
			[]Recorded{{Name: "gw-0", ExternalAddress: "", InstanceID: "1"}}, nil)
		if err == nil {
			t.Fatalf("List: want error, got nil")
		}
		assertMembers(t, snap.Members, []ListedMember{})
		assertDetails(t, snap.Details, map[string]Detail{})
	})

	t.Run("unchanged_fleet_issues_listing_only", func(t *testing.T) {
		srv := newFixtureServer(t)
		srv.pages[""] = pageFixture{status: 200, body: `{"managedInstances":[` +
			managedInstanceJSON("gw-0", "NONE", "1", instanceURL(project, zone, "gw-0"), templateURL(project, revision)) + `]}`}
		s := srv.start()
		defer s.Close()

		snap, err := newTestClient(t, s).List(context.Background(), project, region, mig,
			[]Recorded{{Name: "gw-0", ExternalAddress: "1.1.1.1", InstanceID: "1"}}, nil)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		assertDetails(t, snap.Details, map[string]Detail{})
		assertCalls(t, srv, []string{"POST /compute/v1/projects/proj/regions/us-central1/instanceGroupManagers/gw-mig/listManagedInstances"})
	})

	t.Run("one_pass_issues_only_the_listing_and_its_details", func(t *testing.T) {
		srv := newFixtureServer(t)
		srv.pages[""] = pageFixture{status: 200, body: `{"managedInstances":[` +
			managedInstanceJSON("gw-0", "NONE", "1", instanceURL(project, zone, "gw-0"), templateURL(project, revision)) + `,` + // trigger 1
			managedInstanceJSON("gw-1", "NONE", "789", instanceURL(project, zone, "gw-1"), templateURL(project, revision)) + `,` + // trigger 2
			managedInstanceJSON("gw-2", "NONE", "3", instanceURL(project, zone, "gw-2"), templateURL(project, revision)) + `]}`} // trigger 3
		srv.details["gw-0"] = detailFixture{status: 200, body: instanceDetailJSON("1", "gw-0", "9.9.9.0")}
		srv.details["gw-1"] = detailFixture{status: 200, body: instanceDetailJSON("789", "gw-1", "9.9.9.1")}
		srv.details["gw-2"] = detailFixture{status: 200, body: instanceDetailJSON("3", "gw-2", "9.9.9.2")}
		s := srv.start()
		defer s.Close()

		snap, err := newTestClient(t, s).List(context.Background(), project, region, mig,
			[]Recorded{
				{Name: "gw-0", ExternalAddress: "", InstanceID: "1"},
				{Name: "gw-1", ExternalAddress: "1.1.1.1", InstanceID: "123"},
				{Name: "gw-2", ExternalAddress: "1.1.1.2", InstanceID: "3"},
			}, []string{"gw-2"})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(snap.Details) != 3 {
			t.Fatalf("Details = %v, want exactly 3 entries", snap.Details)
		}
		assertCalls(t, srv, []string{
			"POST /compute/v1/projects/proj/regions/us-central1/instanceGroupManagers/gw-mig/listManagedInstances",
			"GET /compute/v1/projects/proj/zones/us-central1-a/instances/gw-0",
			"GET /compute/v1/projects/proj/zones/us-central1-a/instances/gw-1",
			"GET /compute/v1/projects/proj/zones/us-central1-a/instances/gw-2",
		})
	})
}

func assertMembers(t *testing.T, got, want []ListedMember) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("Members = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Members[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// assertDetails compares the pass's detail reads as a whole: the map holds exactly the names
// a DetailReason authorized this pass.
func assertDetails(t *testing.T, got, want map[string]Detail) {
	t.Helper()
	if !maps.Equal(got, want) {
		t.Fatalf("Details = %+v, want exactly %+v", got, want)
	}
}

func assertCalls(t *testing.T, srv *fixtureServer, want []string) {
	t.Helper()
	got := srv.sortedCalls()
	wantSorted := append([]string(nil), want...)
	sort.Strings(wantSorted)
	if len(got) != len(wantSorted) {
		t.Fatalf("calls = %v, want %v", got, wantSorted)
	}
	for i := range wantSorted {
		if got[i] != wantSorted[i] {
			t.Fatalf("calls = %v, want %v", got, wantSorted)
		}
	}
}

func TestClassify(t *testing.T) {
	actions := []MemberAction{
		ActionNone, ActionCreating, ActionCreatingWithoutRetries, ActionRecreating,
		ActionDeleting, ActionAbandoning, ActionRestarting, ActionRefreshing, ActionVerifying,
	}
	for _, action := range actions {
		for _, hasID := range []bool{false, true} {
			for _, hasRecord := range []bool{false, true} {
				name := string(action) + "/hasID=" + boolLabel(hasID) + "/hasRecord=" + boolLabel(hasRecord)
				t.Run(name, func(t *testing.T) {
					got := Classify(action, hasID, hasRecord)
					want := wantVerdict(action, hasID, hasRecord)
					if got != want {
						t.Fatalf("Classify(%s, %v, %v) = %v, want %v", action, hasID, hasRecord, got, want)
					}
				})
			}
		}
	}
}

// wantVerdict mirrors the classification table's own order independently of Classify's
// implementation, so the test proves the table rather than the code that reads it.
func wantVerdict(action MemberAction, hasID, hasRecord bool) Verdict {
	switch action {
	case ActionDeleting, ActionAbandoning:
		return VerdictDeparted
	case ActionRecreating:
		return VerdictPresent
	case ActionNone, ActionCreating, ActionCreatingWithoutRetries, ActionRestarting, ActionRefreshing, ActionVerifying:
	}
	if !hasID {
		if hasRecord {
			return VerdictPresent
		}
		return VerdictPending
	}
	return VerdictPresent
}

func boolLabel(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestManagedInstanceJSONRoundTrip guards the fixture helper itself: a malformed fixture would
// make every case above pass for the wrong reason.
func TestManagedInstanceJSONRoundTrip(t *testing.T) {
	raw := managedInstanceJSON("gw-0", "NONE", "1", instanceURL("proj", "us-central1-a", "gw-0"), templateURL("proj", "tmpl-1"))
	var decoded map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("managedInstanceJSON produced invalid JSON: %v", err)
	}
	if decoded["name"] != "gw-0" || decoded["currentAction"] != "NONE" || decoded["id"] != "1" {
		t.Fatalf("decoded = %+v, want name=gw-0 currentAction=NONE id=1", decoded)
	}
}
