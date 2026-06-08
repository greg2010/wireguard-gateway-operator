package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	e2eharness "github.com/greg2010/wireguard-gateway-operator/test/harness/e2e"
)

// dataPathDeadline bounds the host-side reachability retries. Gateway readiness
// now gates on the live WireGuard tunnel, so by the time these probes run the
// handshake already exists; this window only covers the residual nftables DNAT
// and route convergence after readiness flips, not the full tunnel bring-up.
const dataPathDeadline = 90 * time.Second

// deniedProbeTimeout bounds a single negative probe. A non-forwarded port is
// dropped at the GCP firewall, so there is no SYN-ACK and no RST (TCP) and no
// reply (UDP); the probe must assert non-delivery within a short fixed window
// rather than retry, since the pass signal is the absence of a response. It is
// kept far below dataPathDeadline so a closed port is not mistaken for a slow
// one and a false pass cannot arise from waiting the full positive budget.
const deniedProbeTimeout = 8 * time.Second

// probeTCPThroughGateway issues an HTTP GET to the gateway's public IP on the
// primary forwarded TCP port and returns the body.
func probeTCPThroughGateway(ctx context.Context, stack *e2eharness.Stack) (string, error) {
	return probeTCPThroughGatewayPort(ctx, stack, stack.TCPPublicPort)
}

// probeTCPThroughGatewayPort issues an HTTP GET to the gateway's public IP on the
// given forwarded TCP port and returns the body. agnhost netexec serves the
// serving pod's name at /hostname, so a non-empty body is the marker proving the
// request traversed gateway -> WireGuard tunnel -> in-cluster echo pod. It takes
// an explicit port so subtests can target the NodePort, cross-namespace, and
// live-added forwards beyond the primary one.
func probeTCPThroughGatewayPort(ctx context.Context, stack *e2eharness.Stack, port int) (string, error) {
	return probeTCPThroughGatewayPortUntil(ctx, stack, port, dataPathDeadline)
}

// probeTCPThroughGatewayPortUntil is probeTCPThroughGatewayPort with an explicit
// retry budget. A forward added or edited after the gateway flips Ready is not
// visible on the data path until the link applies the new nftables rule, and the
// readiness gate (WireGuard handshake freshness) does not trail that apply. Probes
// of a just-changed forward must therefore allow the same edit/lifecycle budget the
// suite gives a Ready-after-edit wait, not the shorter dataPathDeadline that assumes
// the rule is already in place.
func probeTCPThroughGatewayPortUntil(ctx context.Context, stack *e2eharness.Stack, port int, deadline time.Duration) (string, error) {
	var body string
	err := retryUntil(ctx, deadline, func(ctx context.Context) error {
		marker, err := httpMarker(ctx, stack, port)
		if err != nil {
			return err
		}
		body = marker
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("tcp probe %s: %w", markerURL(stack, port), err)
	}
	return body, nil
}

// httpMarker issues one HTTP GET to the gateway's public IP on port and returns
// the trimmed body, the agnhost /hostname serving-pod marker. It is the single
// source of truth for the data-path request, shared by probeTCPThroughGatewayPort
// (which retries it to deadline) and probeUntilMarkerChanges (which polls it for a
// changed marker). A non-200 or transport error is returned so a caller's retry
// loop keeps polling.
func httpMarker(ctx context.Context, stack *e2eharness.Stack, port int) (string, error) {
	url := markerURL(stack, port)
	// Disable keep-alives so every poll dials a fresh connection rather than
	// reusing http.DefaultTransport's shared pool, which could mask a data-path
	// failure by reusing a connection established before a retarget.
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return strings.TrimSpace(string(raw)), nil
}

// markerURL builds the agnhost /hostname URL for the gateway's public IP on port.
func markerURL(stack *e2eharness.Stack, port int) string {
	authority := net.JoinHostPort(stack.Address, strconv.Itoa(port))
	return fmt.Sprintf("http://%s/hostname", authority)
}

// probeUDPThroughGateway sends payload to the gateway's public IP on the forwarded
// UDP port and returns the echoed bytes. agnhost netexec's UDP server only
// replies to commands, so the datagram is the "echo <msg>" command, which returns
// the message through the tunnel.
func probeUDPThroughGateway(ctx context.Context, stack *e2eharness.Stack, payload string) (string, error) {
	addr := net.JoinHostPort(stack.Address, strconv.Itoa(stack.UDPPublicPort))

	dialer := &net.Dialer{}
	var got string
	err := retryUntil(ctx, dataPathDeadline, func(ctx context.Context) error {
		conn, err := dialer.DialContext(ctx, "udp", addr)
		if err != nil {
			return fmt.Errorf("dial udp %s: %w", addr, err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte("echo " + payload)); err != nil {
			return fmt.Errorf("write udp: %w", err)
		}
		buf := make([]byte, len(payload)+64)
		n, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("read udp: %w", err)
		}
		got = strings.TrimSpace(string(buf[:n]))
		if got != payload {
			return fmt.Errorf("udp echo = %q, want %q", got, payload)
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("udp probe %s: %w", addr, err)
	}
	return got, nil
}

// probeTCPDenied asserts that a TCP connect to the gateway's public IP on a
// non-forwarded port does NOT establish within deniedProbeTimeout. The GCP
// firewall opens only the forwarded ports and the WireGuard port, so a SYN to
// any other port is dropped: the dial blocks until the deadline (i/o timeout)
// rather than completing or being refused. A successful connection is the
// failure signal — it would mean the firewall or DNAT closure leaked the port.
func probeTCPDenied(ctx context.Context, stack *e2eharness.Stack, port int) error {
	addr := net.JoinHostPort(stack.Address, strconv.Itoa(port))
	dctx, cancel := context.WithTimeout(ctx, deniedProbeTimeout)
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(dctx, "tcp", addr)
	if err == nil {
		conn.Close()
		return fmt.Errorf("tcp connect to non-forwarded port %s succeeded; want it dropped", addr)
	}
	// Only a timeout proves the SYN was silently dropped by the firewall. A
	// non-timeout error such as connection refused (RST) means the port was
	// reachable but closed, a different posture that must fail the assertion.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return nil
	}
	return fmt.Errorf("tcp connect to non-forwarded port %s failed without timing out (want a dropped SYN, got: %w)", addr, err)
}

// probeUDPDenied asserts that a UDP datagram sent to the gateway's public IP on
// a non-forwarded port draws NO reply within deniedProbeTimeout. agnhost's UDP
// echo replies only on a forwarded path, and the firewall drops the datagram
// before it reaches the VM, so there is also no ICMP error to rely on: silence
// is the pass signal. A reply is the failure signal. This must not reuse the
// positive retry helper, which would wait the full positive deadline.
func probeUDPDenied(ctx context.Context, stack *e2eharness.Stack, port int, payload string) error {
	addr := net.JoinHostPort(stack.Address, strconv.Itoa(port))
	dctx, cancel := context.WithTimeout(ctx, deniedProbeTimeout)
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(dctx, "udp", addr)
	if err != nil {
		// A connectionless UDP "dial" only resolves the address; a failure here
		// is environmental, not a closed-port signal, so surface it.
		return fmt.Errorf("dial udp %s: %w", addr, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(deniedProbeTimeout)); err != nil {
		return fmt.Errorf("set udp deadline: %w", err)
	}
	if _, err := conn.Write([]byte("echo " + payload)); err != nil {
		return fmt.Errorf("write udp %s: %w", addr, err)
	}
	buf := make([]byte, len(payload)+64)
	n, err := conn.Read(buf)
	if err != nil {
		// A read timeout (no reply) is the pass condition for a dropped port.
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil
		}
		// Any other read error (e.g. an ICMP-driven "connection refused") also
		// means no echo was delivered, so it is not a leak.
		return nil
	}
	return fmt.Errorf("udp reply from non-forwarded port %s: %q; want no reply", addr, strings.TrimSpace(string(buf[:n])))
}

// waitPortDenied polls probeTCPDenied until the port is dropped at the firewall or
// deadline elapses, returning the last probe error on timeout. A lifecycle subtest
// that removes or invalidates a forward needs this rather than a single
// probeTCPDenied: closing the forward re-renders the GCP firewall, whose change
// takes time to propagate, so the port stays briefly reachable after the operator
// has re-rendered. The retry waits out that propagation; once the port is closed,
// probeTCPDenied returns nil and the assertion passes.
func waitPortDenied(ctx context.Context, stack *e2eharness.Stack, port int, deadline time.Duration) error {
	dctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var last error
	for {
		last = probeTCPDenied(dctx, stack, port)
		if last == nil {
			return nil
		}
		select {
		case <-dctx.Done():
			return fmt.Errorf("port %d still reachable after %s: %w", port, deadline, last)
		case <-ticker.C:
		}
	}
}

// pingDenied asserts that an ICMP echo to the gateway's public IP draws NO reply
// within deniedProbeTimeout. The GCP firewall no longer allows internet-wide
// ICMP, so a single echo request is dropped.
//
// The pass signal is proof that ping actually sent a probe and got nothing back,
// distinguished from ping failing to run at all. A clean exit means a reply came
// back (the firewall re-opened ICMP) and must fail. A non-zero exit is ambiguous
// on its own: every ping variant exits non-zero both on a legitimate no-reply
// timeout and on a startup error (missing binary, no CAP_NET_RAW / unprivileged
// ping permission, a rejected flag), and a probe that never left the host proves
// nothing. So the transmit/receive summary line ("N packets transmitted, 0 ...
// received") is the authoritative "ran but got no reply" marker; its absence on a
// non-zero exit means ping never probed and the test must fail rather than read a
// broken ping host as a drop. A context-deadline kill is also a pass: the run was
// in flight (it transmitted) and our timeout cut it off before any reply, which is
// the same no-reply outcome for a ping variant that ignores -W.
func pingDenied(ctx context.Context, stack *e2eharness.Stack) error {
	dctx, cancel := context.WithTimeout(ctx, deniedProbeTimeout)
	defer cancel()

	// -c 1 sends one echo request; -W bounds the per-reply wait (whole seconds);
	// -n skips reverse DNS so the run never blocks on a resolver. The context is the
	// outer bound for a variant that ignores -W.
	waitSecs := strconv.Itoa(int(deniedProbeTimeout / time.Second))
	out, err := exec.CommandContext(dctx, "ping", "-c", "1", "-W", waitSecs, "-n", stack.Address).CombinedOutput()
	trimmed := strings.TrimSpace(string(out))
	if err == nil {
		return fmt.Errorf("icmp echo to %s got a reply; want it dropped:\n%s", stack.Address, trimmed)
	}
	if pingTransmittedNoReply(trimmed) || dctx.Err() == context.DeadlineExceeded {
		return nil
	}
	return fmt.Errorf("ping to %s did not run as expected (no probe sent, so the ICMP drop is unproven); err=%v, output:\n%s", stack.Address, err, trimmed)
}

// pingTransmittedNoReply reports whether out carries ping's end-of-run summary
// showing a probe was transmitted and zero replies came back. iputils prints
// "1 packets transmitted, 0 received"; BSD/macOS prints "1 packets transmitted,
// 0 packets received". Matching the transmitted count plus zero received is the
// portable marker that ping ran a probe and was dropped, as opposed to exiting
// before it sent anything.
func pingTransmittedNoReply(out string) bool {
	return strings.Contains(out, "packets transmitted") &&
		(strings.Contains(out, "0 received") || strings.Contains(out, "0 packets received"))
}

// probeUntilMarkerChanges polls the data path until the marker differs from
// before (non-empty), bounded by deadline; proves continuity + convergence to a
// fresh pod across a backend roll where the old pod can briefly stay in endpoints.
//
// It uses retryUntil so each attempt is one httpMarker GET; an unchanged marker
// is returned as an error to keep polling. before must be non-empty (the
// pre-roll marker), so the first fresh pod's distinct name satisfies the change.
func probeUntilMarkerChanges(ctx context.Context, stack *e2eharness.Stack, port int, before string, deadline time.Duration) (string, error) {
	var after string
	err := retryUntil(ctx, deadline, func(ctx context.Context) error {
		marker, err := httpMarker(ctx, stack, port)
		if err != nil {
			return err
		}
		if marker == before {
			return fmt.Errorf("marker still %q; want a fresh pod", before)
		}
		after = marker
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("tcp probe %s: %w", markerURL(stack, port), err)
	}
	return after, nil
}

// retryUntil invokes fn every second until it returns nil or deadline elapses,
// returning fn's last error on timeout.
func retryUntil(ctx context.Context, deadline time.Duration, fn func(context.Context) error) error {
	dctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last error
	for {
		last = fn(dctx)
		if last == nil {
			return nil
		}
		select {
		case <-dctx.Done():
			return last
		case <-ticker.C:
		}
	}
}
