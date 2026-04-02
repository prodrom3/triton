//go:build windows

// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package main

import "os"

// extraSignals returns platform-specific signals to handle for graceful shutdown.
// Windows only supports os.Interrupt (Ctrl+C); SIGTERM does not exist.
func extraSignals() []os.Signal {
	return nil
}
