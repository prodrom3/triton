// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package logging

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxLogFiles = 20

// Setup configures structured logging with optional file output.
// The level parameter controls minimum log level (use slog.LevelInfo for
// verbose mode, slog.LevelWarn for default).
// Returns a cleanup function to close the log file.
func Setup(enableFile bool, stderrLevel slog.Level) func() {
	stderrOpts := &slog.HandlerOptions{Level: stderrLevel}
	stderrHandler := slog.NewTextHandler(os.Stderr, stderrOpts)

	if !enableFile {
		slog.SetDefault(slog.New(stderrHandler))
		return func() {}
	}

	logDir := logDirectory()
	if err := os.MkdirAll(logDir, 0755); err != nil {
		slog.SetDefault(slog.New(stderrHandler))
		return func() {}
	}

	rotateLogFiles(logDir, maxLogFiles)

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	logFile := filepath.Join(logDir, timestamp+".log")
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		slog.SetDefault(slog.New(stderrHandler))
		return func() {}
	}

	fileOpts := &slog.HandlerOptions{Level: slog.LevelInfo}
	fileHandler := slog.NewTextHandler(f, fileOpts)

	slog.SetDefault(slog.New(&multiHandler{
		stderr: stderrHandler,
		file:   fileHandler,
	}))

	return func() { f.Close() }
}

func logDirectory() string {
	exe, err := os.Executable()
	if err != nil {
		return "logs"
	}
	return filepath.Join(filepath.Dir(exe), "logs")
}

func rotateLogFiles(dir string, maxFiles int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var logFiles []os.DirEntry
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".log") {
			logFiles = append(logFiles, e)
		}
	}

	sort.Slice(logFiles, func(i, j int) bool {
		fi, _ := logFiles[i].Info()
		fj, _ := logFiles[j].Info()
		if fi == nil || fj == nil {
			return false
		}
		return fi.ModTime().Before(fj.ModTime())
	})

	for len(logFiles) >= maxFiles {
		oldest := logFiles[0]
		logFiles = logFiles[1:]
		_ = os.Remove(filepath.Join(dir, oldest.Name()))
	}
}

// multiHandler sends records to both stderr and file handlers.
type multiHandler struct {
	stderr slog.Handler
	file   slog.Handler
}

func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return m.stderr.Enabled(ctx, level) || m.file.Enabled(ctx, level)
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	// Always attempt to write to file
	_ = m.file.Handle(ctx, r)
	// Propagate stderr errors so the caller knows if user-visible output failed
	return m.stderr.Handle(ctx, r)
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &multiHandler{
		stderr: m.stderr.WithAttrs(attrs),
		file:   m.file.WithAttrs(attrs),
	}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	return &multiHandler{
		stderr: m.stderr.WithGroup(name),
		file:   m.file.WithGroup(name),
	}
}
