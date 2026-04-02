// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package ping

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/prodrom3/triton/internal/models"
)

// TCPPing measures the TCP connection round-trip time to a host:port.
// Uses a TCP SYN handshake (connect then close) which works without
// elevated privileges on all platforms.
func TCPPing(ctx context.Context, ip string, port int, count int, timeout time.Duration) models.PingResult {
	if count <= 0 {
		count = 3
	}

	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	var rtts []float64
	var failures int

	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return models.PingResult{
				IP:    ip,
				Port:  port,
				Count: i,
				RTTs:  rtts,
				Loss:  calcLoss(i, failures),
				Error: models.Ptr("cancelled"),
			}
		default:
		}

		start := time.Now()
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		elapsed := time.Since(start)

		if err != nil {
			failures++
			continue
		}
		conn.Close()

		ms := float64(elapsed.Microseconds()) / 1000.0
		rtts = append(rtts, ms)
	}

	result := models.PingResult{
		IP:    ip,
		Port:  port,
		Count: count,
		RTTs:  rtts,
		Loss:  calcLoss(count, failures),
	}

	if len(rtts) > 0 {
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

	return result
}

func calcLoss(total, failures int) float64 {
	if total == 0 {
		return 0
	}
	return float64(failures) / float64(total) * 100
}
