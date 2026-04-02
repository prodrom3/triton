//go:build !windows

// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package main

import (
	"os"
	"syscall"
)

// extraSignals returns platform-specific signals to handle for graceful shutdown.
func extraSignals() []os.Signal {
	return []os.Signal{syscall.SIGTERM}
}
