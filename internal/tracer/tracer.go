// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package tracer

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prodrom3/triton/internal/models"
)

var (
	// Linux: matches responding hops like "  1  192.168.1.1  1.234 ms"
	linuxHopRe = regexp.MustCompile(`^\s*(\d+)\s+([\d.]+)\s+([\d.]+)\s+ms`)
	// Linux: matches timed-out hops like "  2  * * *"
	linuxTimeoutRe = regexp.MustCompile(`^\s*(\d+)\s+\*`)
	// Windows: matches responding hops
	windowsHopRe = regexp.MustCompile(`^\s*(\d+)\s+(?:([<\d]+)\s+ms\s+[<\d]+\s+ms\s+[<\d]+\s+ms\s+(\S+)|\*)`)
)

func parseRTT(s string) float64 {
	cleaned := strings.TrimSpace(strings.TrimLeft(s, "<"))
	f, err := strconv.ParseFloat(cleaned, 64)
	if err != nil {
		return 0.0
	}
	return f
}

func parseSystemOutput(output string) []models.TracerouteHop {
	var hops []models.TracerouteHop
	isWindows := strings.Contains(output, "Tracing route") || strings.Contains(strings.ToLower(output), "tracert")

	for _, line := range strings.Split(output, "\n") {
		if isWindows {
			match := windowsHopRe.FindStringSubmatch(line)
			if match != nil {
				ttl, _ := strconv.Atoi(match[1])
				if match[2] != "" {
					rtt := parseRTT(match[2])
					ip := match[3]
					hops = append(hops, models.TracerouteHop{TTL: ttl, IP: ip, RTT: &rtt})
				} else {
					// Timed-out hop on Windows (matched the * branch)
					hops = append(hops, models.TracerouteHop{TTL: ttl, IP: "*"})
				}
			}
		} else {
			match := linuxHopRe.FindStringSubmatch(line)
			if match != nil {
				ttl, _ := strconv.Atoi(match[1])
				ip := match[2]
				rtt := parseRTT(match[3])
				hops = append(hops, models.TracerouteHop{TTL: ttl, IP: ip, RTT: &rtt})
			} else if tmatch := linuxTimeoutRe.FindStringSubmatch(line); tmatch != nil {
				ttl, _ := strconv.Atoi(tmatch[1])
				hops = append(hops, models.TracerouteHop{TTL: ttl, IP: "*"})
			}
		}
	}

	return hops
}

// SystemTraceroute runs the OS traceroute/tracert command and parses the output.
// The provided context controls cancellation.
func SystemTraceroute(ctx context.Context, target string, maxHops int, timeout time.Duration) models.TracerouteResult {
	isWindows := runtime.GOOS == "windows"

	probeTimeout := timeout
	if probeTimeout > 5*time.Second {
		probeTimeout = 5 * time.Second
	}

	cmdCtx, cancel := context.WithTimeout(ctx,
		time.Duration(maxHops)*probeTimeout+10*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if isWindows {
		ms := int(probeTimeout.Milliseconds())
		cmd = exec.CommandContext(cmdCtx, "tracert", "-d", "-h", strconv.Itoa(maxHops),
			"-w", strconv.Itoa(ms), target)
	} else {
		secs := int(probeTimeout.Seconds())
		if secs < 1 {
			secs = 1
		}
		cmd = exec.CommandContext(cmdCtx, "traceroute", "-n", "-m", strconv.Itoa(maxHops),
			"-w", strconv.Itoa(secs), target)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return models.TracerouteResult{
				Target:  target,
				Success: false,
				Error:   models.Ptr("Traceroute cancelled"),
			}
		}
		if cmdCtx.Err() == context.DeadlineExceeded {
			return models.TracerouteResult{
				Target:  target,
				Success: false,
				Error:   models.Ptr("Traceroute timed out"),
			}
		}
		tool := "traceroute"
		if isWindows {
			tool = "tracert"
		}
		if _, lookErr := exec.LookPath(tool); lookErr != nil {
			return models.TracerouteResult{
				Target:  target,
				Success: false,
				Error:   models.Ptr(fmt.Sprintf("%s not found on PATH", tool)),
			}
		}
		// Tool exists but returned a non-zero exit code (permission denied, etc.).
		// Still try to parse partial output, but mark as failed if empty.
		hops := parseSystemOutput(string(out))
		if len(hops) == 0 {
			return models.TracerouteResult{
				Target:  target,
				Success: false,
				Error:   models.Ptr(fmt.Sprintf("Traceroute failed: %v", err)),
			}
		}
		return models.TracerouteResult{Target: target, Success: true, Hops: hops}
	}

	hops := parseSystemOutput(string(out))
	return models.TracerouteResult{Target: target, Success: true, Hops: hops}
}

// EnrichHopsWithRDNS adds reverse DNS hostnames to traceroute hops concurrently.
// Skips timed-out hops (IP == "*").
func EnrichHopsWithRDNS(ctx context.Context, hops []models.TracerouteHop) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for i := range hops {
		if hops[i].IP == "*" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			rdnsCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()

			resolver := net.DefaultResolver
			names, err := resolver.LookupAddr(rdnsCtx, hops[idx].IP)
			if err != nil || len(names) == 0 {
				return
			}
			hostname := strings.TrimRight(names[0], ".")
			if hostname != hops[idx].IP {
				hops[idx].Hostname = &hostname
			}
		}(i)
	}

	wg.Wait()
}

// PerformTraceroute runs a traceroute and enriches hops with reverse DNS.
func PerformTraceroute(ctx context.Context, target string, maxHops int, timeout time.Duration) models.TracerouteResult {
	result := SystemTraceroute(ctx, target, maxHops, timeout)

	if result.Success && len(result.Hops) > 0 {
		sort.Slice(result.Hops, func(i, j int) bool {
			return result.Hops[i].TTL < result.Hops[j].TTL
		})
		EnrichHopsWithRDNS(ctx, result.Hops)
	}

	return result
}
