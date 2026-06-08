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

// dataPathDeadline bounds the host-side reachability retries: only the residual
// nftables DNAT and route convergence after readiness flips, not tunnel bring-up,
// which readiness already gates on.
const dataPathDeadline = 90 * time.Second

// deniedProbeTimeout bounds a single negative probe, whose pass signal is the
// absence of a response. Kept far below dataPathDeadline so a closed port is not
// mistaken for a slow one.
const deniedProbeTimeout = 8 * time.Second

// probeTCPThroughGateway issues an HTTP GET to the gateway's public IP on the
// primary forwarded TCP port and returns the body.
func probeTCPThroughGateway(ctx context.Context, stack *e2eharness.Stack) (string, error) {
	return probeTCPThroughGatewayPort(ctx, stack, stack.TCPPublicPort)
}

// probeTCPThroughGatewayPort issues an HTTP GET to the gateway's public IP on the
// given forwarded TCP port and returns the body, the agnhost /hostname marker that
// proves the request traversed the tunnel to an in-cluster echo pod.
func probeTCPThroughGatewayPort(ctx context.Context, stack *e2eharness.Stack, port int) (string, error) {
	return probeTCPThroughGatewayPortUntil(ctx, stack, port, dataPathDeadline)
}

// probeTCPThroughGatewayPortUntil is probeTCPThroughGatewayPort with an explicit
// retry budget, for a just-changed forward whose new nftables rule the readiness
// gate does not trail.
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

// httpMarker issues one HTTP GET on port and returns the trimmed body, the agnhost
// /hostname marker. A non-200 or transport error is returned so a caller's retry
// loop keeps polling.
func httpMarker(ctx context.Context, stack *e2eharness.Stack, port int) (string, error) {
	url := markerURL(stack, port)
	// Dial fresh every poll so a connection reused from before a retarget cannot
	// mask a data-path failure.
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

// probeUDPThroughGateway sends payload to the forwarded UDP port and returns the
// echoed bytes. agnhost's UDP server replies only to commands, hence the "echo
// <msg>" datagram.
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

// probeTCPDenied asserts a TCP connect to a non-forwarded port does NOT establish
// within deniedProbeTimeout; the GCP firewall drops the SYN so the dial times out.
// A successful connection is the failure signal.
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
	// Only a timeout proves a dropped SYN; a refused (RST) means the port was
	// reachable but closed, which must fail.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return nil
	}
	return fmt.Errorf("tcp connect to non-forwarded port %s failed without timing out (want a dropped SYN, got: %w)", addr, err)
}

// probeUDPDenied asserts that a UDP datagram to a non-forwarded port draws NO reply
// within deniedProbeTimeout: silence is the pass signal, a reply is the failure. It
// must not reuse the positive retry helper, which would wait the full deadline.
func probeUDPDenied(ctx context.Context, stack *e2eharness.Stack, port int, payload string) error {
	addr := net.JoinHostPort(stack.Address, strconv.Itoa(port))
	dctx, cancel := context.WithTimeout(ctx, deniedProbeTimeout)
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(dctx, "udp", addr)
	if err != nil {
		// A connectionless UDP dial only resolves the address, so a failure here is
		// environmental, not a closed-port signal.
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
		// Any other read error (e.g. an ICMP-driven refused) also means no echo was
		// delivered, so it is not a leak.
		return nil
	}
	return fmt.Errorf("udp reply from non-forwarded port %s: %q; want no reply", addr, strings.TrimSpace(string(buf[:n])))
}

// waitPortDenied polls probeTCPDenied until the port is dropped or deadline
// elapses, returning the last probe error on timeout. It waits out the firewall
// re-render a closed forward triggers, which leaves the port briefly reachable.
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

// pingDenied asserts an ICMP echo draws NO reply within deniedProbeTimeout. Ping
// exits non-zero on both a drop and a startup error, so the no-reply pass keys on
// the transmit/receive summary line (or a context kill), never the exit code alone.
func pingDenied(ctx context.Context, stack *e2eharness.Stack) error {
	dctx, cancel := context.WithTimeout(ctx, deniedProbeTimeout)
	defer cancel()

	// -W bounds the per-reply wait (whole seconds); -n skips reverse DNS. The
	// context is the outer bound for a variant that ignores -W.
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

// pingTransmittedNoReply reports whether out carries ping's summary showing a probe
// was transmitted and zero replies came back, the portable marker that ping ran and
// was dropped. iputils prints "0 received"; BSD/macOS prints "0 packets received".
func pingTransmittedNoReply(out string) bool {
	return strings.Contains(out, "packets transmitted") &&
		(strings.Contains(out, "0 received") || strings.Contains(out, "0 packets received"))
}

// probeUntilMarkerChanges polls until the marker differs from before (non-empty),
// proving convergence to a fresh pod across a backend roll where the old pod can
// briefly stay in endpoints. before must be the non-empty pre-roll marker.
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
