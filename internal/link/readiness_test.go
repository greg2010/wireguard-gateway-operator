package link

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestFreshestHandshake(t *testing.T) {
	tcs := []struct {
		name      string
		output    string
		wantOK    bool
		wantEpoch int64
	}{
		{
			name:   "empty",
			output: "",
			wantOK: false,
		},
		{
			name:   "single_zero_epoch",
			output: "PUBKEY=\t0",
			wantOK: false,
		},
		{
			name:      "single_fresh",
			output:    "PUBKEY=\t1700000000",
			wantOK:    true,
			wantEpoch: 1700000000,
		},
		{
			name:      "newest_of_many",
			output:    "PK1=\t1700000000\nPK2=\t1700000500\nPK3=\t0\n",
			wantOK:    true,
			wantEpoch: 1700000500,
		},
		{
			name:   "garbage_lines_ignored",
			output: "not-a-handshake\n\nPK=\tnotanumber\n",
			wantOK: false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			ts, ok := freshestHandshake(tc.output)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && ts.Unix() != tc.wantEpoch {
				t.Errorf("epoch = %d, want %d", ts.Unix(), tc.wantEpoch)
			}
		})
	}
}

// singleSlotApplied is the one-slot []SlotResult most readiness cases below drive kubeletStatus
// with: slot 0 applied and nothing else.
var singleSlotApplied = []SlotResult{{Slot: 0, Applied: true}}

func TestReadinessReady(t *testing.T) {
	const nowEpoch = int64(1700001000)
	now := func() time.Time { return time.Unix(nowEpoch, 0) }
	const gatewayID = 3 // NewSlotIdentity(3, 0).Interface == "wg-gw3"

	tcs := []struct {
		name      string
		leader    bool
		keepalive int
		nodeFault string
		fault     string
		slots     []SlotResult
		showOut   string
		showErr   error
		want      bool
		// wantBody is the /healthz failure body, empty on a ready row.
		wantBody string
	}{
		{
			name:      "leader_fresh_within_keepalive_window",
			leader:    true,
			keepalive: 25, // staleness = max(75s, 150s) = 150s
			slots:     singleSlotApplied,
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-30),
			want:      true,
		},
		{
			name:      "leader_handshake_aged_past_keepalive_but_within_rekey_floor",
			leader:    true,
			keepalive: 25, // staleness floor = 150s covers the ~120s rekey interval
			slots:     singleSlotApplied,
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-120),
			want:      true,
		},
		{
			name:      "leader_stale_beyond_rekey_floor",
			leader:    true,
			keepalive: 25, // staleness = max(75s, 150s) = 150s
			slots:     singleSlotApplied,
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-200),
			want:      false,
			wantBody:  "no recent handshake",
		},
		{
			name:      "leader_no_handshake",
			leader:    true,
			keepalive: 25,
			slots:     singleSlotApplied,
			showOut:   "PK=\t0",
			want:      false,
			wantBody:  "no recent handshake",
		},
		{
			name:      "leader_wg_show_error",
			leader:    true,
			keepalive: 25,
			slots:     singleSlotApplied,
			showErr:   fmt.Errorf("wg0 does not exist"),
			want:      false,
			wantBody:  "no recent handshake",
		},
		{
			name:      "leader_keepalive_zero_fresh_within_default_window",
			leader:    true,
			keepalive: 0, // staleness = 180s
			slots:     singleSlotApplied,
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-120),
			want:      true,
		},
		{
			name:      "leader_keepalive_zero_stale_beyond_default_window",
			leader:    true,
			keepalive: 0, // staleness = 180s
			slots:     singleSlotApplied,
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-200),
			want:      false,
			wantBody:  "no recent handshake",
		},
		{
			name:      "standby_ready_despite_stale_handshake",
			leader:    false,
			keepalive: 25,
			slots:     singleSlotApplied,
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-3600),
			want:      true,
		},
		{
			name:      "standby_ready_despite_no_handshake",
			leader:    false,
			keepalive: 25,
			slots:     singleSlotApplied,
			showOut:   "PK=\t0",
			want:      true,
		},
		{
			name:      "standby_ready_despite_wg_show_error",
			leader:    false,
			keepalive: 25,
			slots:     singleSlotApplied,
			showErr:   fmt.Errorf("wg0 does not exist"),
			want:      true,
		},
		{
			name:   "standby_ready_with_empty_fault",
			leader: false,
			fault:  "",
			want:   true,
		},
		{
			name:     "standby_not_ready_with_rp_filter_strict_fault",
			leader:   false,
			fault:    FaultRPFilterStrict,
			want:     false,
			wantBody: "node fault: " + FaultRPFilterStrict,
		},
		{
			name:     "standby_not_ready_with_apply_failed_fault",
			leader:   false,
			fault:    FaultApplyFailed,
			want:     false,
			wantBody: "node fault: " + FaultApplyFailed,
		},
		{
			name:      "leader_not_ready_with_node_fault",
			leader:    true,
			keepalive: 25,
			slots:     singleSlotApplied,
			nodeFault: FaultRPFilterStrict,
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-30),
			want:      false,
			wantBody:  "node fault: " + FaultRPFilterStrict,
		},
		{
			name:      "leader_not_ready_with_reload_loop_fault",
			leader:    true,
			keepalive: 25,
			slots:     singleSlotApplied,
			fault:     FaultApplyFailed,
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-30),
			want:      false,
			wantBody:  "node fault: " + FaultApplyFailed,
		},
		{
			name:      "leader_ready_with_fresh_handshake_and_no_fault",
			leader:    true,
			keepalive: 25,
			slots:     singleSlotApplied,
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-30),
			want:      true,
		},
		{
			name:      "one_stale_one_live_slot_stays_ready",
			leader:    true,
			keepalive: 25,
			slots:     []SlotResult{{Slot: 0, Applied: true}, {Slot: 2, Applied: true}},
			want:      true, // per-slot showOut below distinguishes stale from live
		},
		{
			name:      "no_live_slot_unready",
			leader:    true,
			keepalive: 25,
			slots:     []SlotResult{{Slot: 0, Applied: true}, {Slot: 2, Applied: true}},
			want:      false, // per-slot showOut below leaves both slots stale
			wantBody:  "no recent handshake",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			wgShow := func(_ context.Context, gotIface string) (string, error) {
				switch tc.name {
				case "one_stale_one_live_slot_stays_ready":
					if gotIface == "wg-gw3-2" {
						return fmt.Sprintf("PK=\t%d", nowEpoch-30), nil
					}
					return fmt.Sprintf("PK=\t%d", nowEpoch-3600), nil
				case "no_live_slot_unready":
					return fmt.Sprintf("PK=\t%d", nowEpoch-3600), nil
				default:
					if gotIface != "wg-gw3" {
						t.Errorf("wgShow iface = %q, want %q", gotIface, "wg-gw3")
					}
					return tc.showOut, tc.showErr
				}
			}
			rd := newReadiness(true, gatewayID, now, wgShow, testLogger(t))
			rd.setLeader(tc.leader)
			rd.setNodeFault(tc.nodeFault)
			rd.setFault(tc.fault)
			rd.setPass(tc.slots, len(tc.slots), tc.keepalive, true)
			ready, body := rd.kubeletStatus(context.Background())
			if ready != tc.want {
				t.Errorf("kubeletStatus ready = %v, want %v (leader=%v, staleness=%s)", ready, tc.want, tc.leader, rd.staleness())
			}
			if body != tc.wantBody {
				t.Errorf("kubeletStatus body = %q, want %q", body, tc.wantBody)
			}
		})
	}
}

// TestReadinessStandbyIgnoresWGShow pins that a non-leader never shells out for
// handshake state: kubeletStatus must short-circuit to true before calling wgShow.
func TestReadinessStandbyIgnoresWGShow(t *testing.T) {
	called := false
	rd := newReadiness(true, 3, time.Now, func(_ context.Context, _ string) (string, error) {
		called = true
		return "", fmt.Errorf("wgShow must not be called for a standby")
	}, testLogger(t))
	rd.setPass(singleSlotApplied, 1, 25, true)

	if ready, body := rd.kubeletStatus(context.Background()); !ready || body != "" {
		t.Fatalf("standby kubeletStatus = (%v, %q), want (true, \"\")", ready, body)
	}
	if called {
		t.Error("wgShow was called for a non-leader; kubeletStatus must short-circuit first")
	}
}

// TestReadinessNotReadyMessage pins that a standby held down by a node fault says so rather than
// blaming a handshake it never makes, and that the leader keeps its stale-tunnel wording.
func TestReadinessNotReadyMessage(t *testing.T) {
	const nowEpoch = int64(1700001000)
	now := func() time.Time { return time.Unix(nowEpoch, 0) }

	tcs := []struct {
		name   string
		leader bool
		fault  string
		want   string
	}{
		{
			name:  "standby_rp_filter_strict_names_the_fault",
			fault: FaultRPFilterStrict,
			want:  "node fault: RPFilterStrict",
		},
		{
			name:  "standby_apply_failed_names_the_fault",
			fault: FaultApplyFailed,
			want:  "node fault: ApplyFailed",
		},
		{
			name:   "leader_stale_handshake_keeps_handshake_message",
			leader: true,
			want:   "no recent handshake",
		},
		{
			name:   "leader_with_fault_names_the_fault",
			leader: true,
			fault:  FaultRPFilterStrict,
			want:   "node fault: RPFilterStrict",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rd := newReadiness(true, 3, now, func(context.Context, string) (string, error) {
				return "PK=\t0", nil
			}, testLogger(t))
			rd.setLeader(tc.leader)
			rd.setFault(tc.fault)
			rd.setPass(singleSlotApplied, 1, 25, true)

			rec := httptest.NewRecorder()
			rd.handler(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
			}
			if got := rec.Body.String(); got != tc.want {
				t.Errorf("body = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestReadinessFaultSlotsStepDown pins the two fault slots: the loop's fault clears on step down,
// so one failed apply does not bar the pod for life, and the node fault outranks and survives it.
func TestReadinessFaultSlotsStepDown(t *testing.T) {
	tcs := []struct {
		name            string
		nodeFault       string
		loopFault       string
		wantWhileLeader string
		wantAfterStep   string
	}{
		{
			name:            "loop_fault_clears_on_step_down",
			loopFault:       FaultApplyFailed,
			wantWhileLeader: FaultApplyFailed,
		},
		{
			name:            "pre_check_fault_outranks_and_survives",
			nodeFault:       FaultRPFilterStrict,
			loopFault:       FaultApplyFailed,
			wantWhileLeader: FaultRPFilterStrict,
			wantAfterStep:   FaultRPFilterStrict,
		},
		{
			name: "no_fault_stays_ready",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rd := newReadiness(true, 1, time.Now, nil, testLogger(t))
			rd.setNodeFault(tc.nodeFault)
			rd.setFault(tc.loopFault)
			if got := rd.gatingFault(); got != tc.wantWhileLeader {
				t.Errorf("gating fault before step down = %q, want %q", got, tc.wantWhileLeader)
			}

			rd.setFault("")
			if got := rd.gatingFault(); got != tc.wantAfterStep {
				t.Errorf("gating fault after step down = %q, want %q", got, tc.wantAfterStep)
			}
		})
	}
}

// TestHealthzFaultfreeStandby accepts a fault-free standby.
func TestHealthzFaultfreeStandby(t *testing.T) {
	rd := newReadiness(true, 3, time.Now, nil, testLogger(t))
	rd.setLeader(false)

	rec := httptest.NewRecorder()
	rd.handler(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got != "ok" {
		t.Errorf("body = %q, want %q", got, "ok")
	}
}

// passOutcome records a completed apply pass for readiness tests.
type passOutcome struct {
	slots   []SlotResult
	peers   int
	applied bool
}

// TestReadyKubeletContract covers readiness for faults, standby, and applied holders.
func TestReadyKubeletContract(t *testing.T) {
	const nowEpoch = int64(1700001000)
	now := func() time.Time { return time.Unix(nowEpoch, 0) }
	fresh := fmt.Sprintf("PK=\t%d", nowEpoch-30)
	stale := fmt.Sprintf("PK=\t%d", nowEpoch-3600)
	bothSlots := []SlotResult{{Slot: 0, Applied: true}, {Slot: 2, Applied: true}}

	tcs := []struct {
		name      string
		local     bool
		leader    bool
		nodeFault string
		fault     string
		pass      *passOutcome
		showOut   string
		showErr   error
		want      bool
		wantBody  string
	}{
		{
			name:     "standby_faultfree_is_ready",
			local:    true,
			want:     true,
			wantBody: "",
		},
		{
			name:      "standby_with_a_node_fault_is_unready",
			local:     true,
			nodeFault: FaultRPFilterStrict,
			pass:      &passOutcome{slots: bothSlots, peers: 2, applied: true},
			showOut:   fresh,
			want:      false,
			wantBody:  "node fault: " + FaultRPFilterStrict,
		},
		{
			name:     "holder_with_an_apply_fault_is_unready",
			local:    true,
			leader:   true,
			fault:    FaultApplyFailed,
			pass:     &passOutcome{slots: bothSlots, peers: 2, applied: true},
			showOut:  fresh,
			want:     false,
			wantBody: "node fault: " + FaultApplyFailed,
		},
		{
			name:     "local_holder_before_any_completed_pass_is_unready",
			local:    true,
			leader:   true,
			want:     false,
			wantBody: "no recent handshake",
		},
		{
			name:     "cluster_holder_before_any_completed_pass_is_unready",
			leader:   true,
			want:     false,
			wantBody: "no recent handshake",
		},
		{
			name:     "cluster_holder_with_a_peer_and_a_fresh_handshake_is_ready",
			leader:   true,
			pass:     &passOutcome{peers: 1, applied: true},
			showOut:  fresh,
			want:     true,
			wantBody: "",
		},
		{
			name:     "cluster_holder_with_no_configured_peer_is_unready",
			leader:   true,
			pass:     &passOutcome{peers: 0, applied: true},
			want:     false,
			wantBody: "no peers configured",
		},
		{
			name:     "cluster_holder_with_a_peer_and_a_stale_handshake_is_unready",
			leader:   true,
			pass:     &passOutcome{peers: 1, applied: true},
			showOut:  stale,
			want:     false,
			wantBody: "no recent handshake",
		},
		{
			name:     "cluster_holder_with_a_peer_and_a_wg_show_error_is_unready",
			leader:   true,
			pass:     &passOutcome{peers: 1, applied: true},
			showErr:  fmt.Errorf("wg0 does not exist"),
			want:     false,
			wantBody: "no recent handshake",
		},
		{
			name:     "cluster_holder_with_a_peer_and_no_handshake_timestamp_is_unready",
			leader:   true,
			pass:     &passOutcome{peers: 1, applied: true},
			showOut:  "PK=\t0",
			want:     false,
			wantBody: "no recent handshake",
		},
		{
			name:     "cluster_holder_whose_pass_failed_is_unready",
			leader:   true,
			pass:     &passOutcome{peers: 1},
			showOut:  fresh,
			want:     false,
			wantBody: "no recent handshake",
		},
		{
			name:     "local_holder_with_a_peer_is_ready_on_an_applied_slot_with_a_fresh_handshake",
			local:    true,
			leader:   true,
			pass:     &passOutcome{slots: bothSlots, peers: 2, applied: true},
			showOut:  fresh,
			want:     true,
			wantBody: "",
		},
		{
			name:     "local_holder_with_a_peer_and_no_applied_slot_is_unready",
			local:    true,
			leader:   true,
			pass:     &passOutcome{slots: []SlotResult{{Slot: 0}}, peers: 1, applied: true},
			showOut:  fresh,
			want:     false,
			wantBody: "no recent handshake",
		},
		{
			name:     "local_holder_with_a_peer_and_only_stale_handshakes_is_unready",
			local:    true,
			leader:   true,
			pass:     &passOutcome{slots: bothSlots, peers: 2, applied: true},
			showOut:  stale,
			want:     false,
			wantBody: "no recent handshake",
		},
		{
			name:     "local_pending_fleet_is_ready_once_its_empty_pass_applied",
			local:    true,
			leader:   true,
			pass:     &passOutcome{slots: []SlotResult{}, applied: true},
			want:     true,
			wantBody: "",
		},
		{
			name:     "local_pending_fleet_whose_empty_pass_failed_is_unready",
			local:    true,
			leader:   true,
			pass:     &passOutcome{slots: []SlotResult{}},
			want:     false,
			wantBody: "no recent handshake",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rd := newReadiness(tc.local, 3, now, func(_ context.Context, iface string) (string, error) {
				if !tc.local && iface != clusterInterface {
					t.Errorf("wgShow iface = %q, want %q", iface, clusterInterface)
				}
				return tc.showOut, tc.showErr
			}, testLogger(t))
			rd.setLeader(tc.leader)
			rd.setNodeFault(tc.nodeFault)
			rd.setFault(tc.fault)
			if tc.pass != nil {
				rd.setPass(tc.pass.slots, tc.pass.peers, 25, tc.pass.applied)
			}
			ready, body := rd.kubeletStatus(context.Background())
			if ready != tc.want {
				t.Errorf("kubeletStatus ready = %v, want %v", ready, tc.want)
			}
			if body != tc.wantBody {
				t.Errorf("kubeletStatus body = %q, want %q", body, tc.wantBody)
			}
			// For leaders without gating faults, tunnelStatus must exactly match kubeletStatus because
			// gatingFault is the only check kubeletStatus performs that tunnelStatus does not.
			if tc.leader && tc.nodeFault == "" && tc.fault == "" {
				if tsReady, tsBody := rd.tunnelStatus(context.Background()); tsReady != tc.want || tsBody != tc.wantBody {
					t.Errorf("tunnelStatus = (%v, %q), want (%v, %q)", tsReady, tsBody, tc.want, tc.wantBody)
				}
			}
		})
	}
}

// TestHealthzAcrossALeadershipTransition pins the pass gate across a leadership change: a replica
// that applied, stepped down and reacquired is a holder before a pass, unready until one applies.
func TestHealthzAcrossALeadershipTransition(t *testing.T) {
	rd := newReadiness(true, 3, time.Now, nil, testLogger(t))

	steps := []struct {
		name        string
		act         func()
		wantHealthz int
	}{
		{
			name:        "first_cycle_applied_an_empty_fleet",
			act:         func() { rd.setLeader(true); rd.setPass([]SlotResult{}, 0, 0, true) },
			wantHealthz: http.StatusOK,
		},
		{
			name:        "stepped_down",
			act:         func() { rd.setLeader(false); rd.setFault("") },
			wantHealthz: http.StatusOK,
		},
		{
			name:        "reacquired_before_its_first_pass",
			act:         func() { rd.setLeader(true) },
			wantHealthz: http.StatusServiceUnavailable,
		},
		{
			name:        "first_pass_of_the_new_cycle_applied",
			act:         func() { rd.setPass([]SlotResult{}, 0, 0, true) },
			wantHealthz: http.StatusOK,
		},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			step.act()
			if got := probeCode(rd.handler, "/healthz"); got != step.wantHealthz {
				t.Errorf("/healthz status = %d, want %d", got, step.wantHealthz)
			}
		})
	}
}

// probeCode is the status code handler answers a GET on path with.
func probeCode(handler func(http.ResponseWriter, *http.Request), path string) int {
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code
}

type failingReadinessWriter struct {
	header http.Header
}

func (w *failingReadinessWriter) Header() http.Header { return w.header }
func (w *failingReadinessWriter) WriteHeader(int)     {}
func (w *failingReadinessWriter) Write([]byte) (int, error) {
	return 0, fmt.Errorf("response closed")
}

func TestReadinessLogsFailures(t *testing.T) {
	now := time.Unix(1_700_001_000, 0)
	tcs := []struct {
		name        string
		local       bool
		writer      http.ResponseWriter
		wantBody    string
		wantMessage string
		wantLog     map[string]any
	}{
		{
			name:        "cluster_wg_show_failure_logs_the_interface_command_and_error",
			wantBody:    bodyNoHandshake,
			wantMessage: "read cluster interface handshakes",
			wantLog: map[string]any{
				"interface": clusterInterface,
				"command":   "wg show wg0 latest-handshakes",
				"error":     "wg show failed",
			},
		},
		{
			name:        "local_wg_show_failure_logs_the_slot_interface_command_and_error",
			local:       true,
			wantBody:    bodyNoHandshake,
			wantMessage: "read slot interface handshakes",
			wantLog: map[string]any{
				"slot":      int64(0),
				"interface": "wg-gw3",
				"command":   "wg show wg-gw3 latest-handshakes",
				"error":     "wg show failed",
			},
		},
		{
			name:        "readiness_response_write_failure_logs_the_error",
			writer:      &failingReadinessWriter{header: make(http.Header)},
			wantMessage: "write readiness response",
			wantLog:     map[string]any{"error": "response closed"},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zap.WarnLevel)
			rd := newReadiness(tc.local, 3, func() time.Time { return now }, func(context.Context, string) (string, error) {
				return "", fmt.Errorf("wg show failed")
			}, zap.New(core).Sugar())
			rd.setLeader(true)
			rd.setPass([]SlotResult{{Slot: 0, Applied: true}}, 1, 25, true)
			if tc.writer == nil {
				tc.writer = httptest.NewRecorder()
			}
			if tc.wantBody == "" {
				rd.writeReadinessBody(tc.writer, "ok")
			} else {
				rd.handler(tc.writer, httptest.NewRequest(http.MethodGet, "/healthz", nil))
			}
			if rec, ok := tc.writer.(*httptest.ResponseRecorder); ok && rec.Body.String() != tc.wantBody {
				t.Errorf("body = %q, want %q", rec.Body.String(), tc.wantBody)
			}
			entries := logs.All()
			if len(entries) != 1 {
				t.Fatalf("log entries = %d, want 1", len(entries))
			}
			if entries[0].Message != tc.wantMessage {
				t.Errorf("log message = %q, want %q", entries[0].Message, tc.wantMessage)
			}
			if got := entries[0].ContextMap(); !maps.Equal(got, tc.wantLog) {
				t.Errorf("log fields = %v, want %v", got, tc.wantLog)
			}
		})
	}
}

func TestReadinessUsesPassKeepalive(t *testing.T) {
	const nowEpoch = int64(1_700_001_000)
	tcs := []struct {
		name      string
		passes    []int
		wantReady bool
		wantBody  string
	}{
		{
			name:     "first_peer_pass_uses_its_keepalive_instead_of_startup_empty_config",
			passes:   []int{25},
			wantBody: bodyNoHandshake,
		},
		{
			name:      "later_peer_pass_updates_the_staleness_window",
			passes:    []int{25, 100},
			wantReady: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rd := newReadiness(false, 0, func() time.Time { return time.Unix(nowEpoch, 0) }, func(context.Context, string) (string, error) {
				return fmt.Sprintf("PK=\t%d", nowEpoch-160), nil
			}, testLogger(t))
			rd.setLeader(true)
			for _, keepalive := range tc.passes {
				rd.setPass(nil, 1, keepalive, true)
			}
			ready, body := rd.kubeletStatus(context.Background())
			if ready != tc.wantReady || body != tc.wantBody {
				t.Errorf("kubeletStatus = (%v, %q), want (%v, %q)", ready, body, tc.wantReady, tc.wantBody)
			}
		})
	}
}
