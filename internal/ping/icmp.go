// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package ping

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/prodrom3/triton/internal/models"
)

// ICMPPing sends ICMP echo requests to ip and measures round-trip time. It first
// tries an unprivileged datagram socket (works on Linux when
// net.ipv4.ping_group_range permits, and on macOS) and falls back to a raw
// socket. When neither is permitted the result carries a clear error rather than
// panicking, so callers can surface a privilege hint.
func ICMPPing(ctx context.Context, ip string, count int, timeout time.Duration) models.PingResult {
	if count <= 0 {
		count = 3
	}
	result := models.PingResult{IP: ip, Protocol: "icmp", Count: count}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		result.Error = models.Ptr("invalid IP address")
		return result
	}
	isV6 := parsed.To4() == nil
	if isV6 && parsed.IsLinkLocalUnicast() {
		// A link-local destination needs a zone/scope id that the scan pipeline
		// does not carry, so the send would fail and look like 100% loss.
		result.Error = models.Ptr("link-local IPv6 ICMP requires a zone (for example fe80::1%eth0), which is not supported")
		return result
	}

	var listenNet, rawNet string
	var proto int
	var echoType icmp.Type
	if isV6 {
		listenNet, rawNet, proto, echoType = "udp6", "ip6:ipv6-icmp", 58, ipv6.ICMPTypeEchoRequest
	} else {
		listenNet, rawNet, proto, echoType = "udp4", "ip4:icmp", 1, ipv4.ICMPTypeEcho
	}

	conn, privileged, err := listenICMP(listenNet, rawNet)
	if err != nil {
		result.Error = models.Ptr(fmt.Sprintf("ICMP not permitted (needs elevated privileges or CAP_NET_RAW): %v", err))
		return result
	}
	defer conn.Close()

	// Unblock a pending read promptly when the context is cancelled.
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Now())
		case <-watchDone:
		}
	}()

	id := os.Getpid() & 0xffff
	var dst net.Addr = &net.UDPAddr{IP: parsed}
	if privileged {
		dst = &net.IPAddr{IP: parsed}
	}

	perProbe := timeout
	if perProbe <= 0 {
		perProbe = 2 * time.Second
	}

	var rtts []float64
	var failures int
	sent := 0
	for seq := 0; seq < count; seq++ {
		if ctx.Err() != nil {
			result.Count = sent
			result.Loss = calcLoss(sent, failures)
			result.Error = models.Ptr("cancelled")
			finalizeStats(&result, rtts)
			return result
		}
		sent++

		msg := icmp.Message{
			Type: echoType, Code: 0,
			Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("triton-icmp")},
		}
		wb, err := msg.Marshal(nil)
		if err != nil {
			failures++
			continue
		}
		start := time.Now()
		if _, err := conn.WriteTo(wb, dst); err != nil {
			failures++
			continue
		}
		if awaitEchoReply(conn, proto, parsed, id, seq, privileged, perProbe) {
			rtts = append(rtts, float64(time.Since(start).Microseconds())/1000.0)
		} else {
			failures++
		}
	}

	result.Count = sent
	result.Loss = calcLoss(sent, failures)
	finalizeStats(&result, rtts)
	return result
}

// listenICMP opens an ICMP socket, preferring the unprivileged datagram form.
func listenICMP(datagramNet, rawNet string) (*icmp.PacketConn, bool, error) {
	if c, err := icmp.ListenPacket(datagramNet, ""); err == nil {
		return c, false, nil
	}
	c, err := icmp.ListenPacket(rawNet, "")
	if err != nil {
		return nil, false, err
	}
	return c, true, nil
}

// awaitEchoReply waits up to timeout for the echo reply to wantSeq from want,
// ignoring other ICMP traffic (stale, reordered, or foreign replies). The
// sequence number is echoed back unchanged on both socket types, so matching it
// prevents a delayed reply from being attributed to the wrong probe. On a raw
// socket, which receives every host's echo replies, the ID is also verified; on
// a datagram socket the kernel rewrites the ID (and already filters by it), so
// only the sequence is checked there.
func awaitEchoReply(conn *icmp.PacketConn, proto int, want net.IP, wantID, wantSeq int, privileged bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)
	rb := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return false
		}
		if !peerMatches(peer, want) {
			continue
		}
		rm, err := icmp.ParseMessage(proto, rb[:n])
		if err != nil {
			continue
		}
		if rm.Type != ipv4.ICMPTypeEchoReply && rm.Type != ipv6.ICMPTypeEchoReply {
			continue
		}
		echo, ok := rm.Body.(*icmp.Echo)
		if !ok || echo.Seq != wantSeq {
			continue
		}
		if privileged && echo.ID != wantID {
			continue
		}
		return true
	}
}

func peerMatches(peer net.Addr, want net.IP) bool {
	switch a := peer.(type) {
	case *net.UDPAddr:
		return a.IP.Equal(want)
	case *net.IPAddr:
		return a.IP.Equal(want)
	}
	return false
}

func finalizeStats(result *models.PingResult, rtts []float64) {
	result.RTTs = rtts
	if len(rtts) == 0 {
		return
	}
	min, max, sum := rtts[0], rtts[0], 0.0
	for _, r := range rtts {
		sum += r
		if r < min {
			min = r
		}
		if r > max {
			max = r
		}
	}
	avg := sum / float64(len(rtts))
	result.Min = &min
	result.Max = &max
	result.Avg = &avg
}
