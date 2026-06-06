package e2e_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
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
// forwarded TCP port and returns the body. agnhost netexec serves the serving
// pod's name at /hostname, so a non-empty body is the marker proving the
// request traversed gateway -> WireGuard tunnel -> in-cluster echo pod.
func probeTCPThroughGateway(ctx context.Context, stack *e2eharness.Stack) (string, error) {
	authority := net.JoinHostPort(stack.Address, strconv.Itoa(stack.TCPPublicPort))
	url := fmt.Sprintf("http://%s/hostname", authority)
	client := &http.Client{Timeout: 5 * time.Second}

	var body string
	err := retryUntil(ctx, dataPathDeadline, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
		}
		body = strings.TrimSpace(string(raw))
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("tcp probe %s: %w", url, err)
	}
	return body, nil
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
	// Any non-success (timeout, or an unexpected refusal) means the port did not
	// deliver a usable connection, which is the pass condition.
	return nil
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
