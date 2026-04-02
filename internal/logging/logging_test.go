// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package logging

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestRotateLogFiles(t *testing.T) {
	dir := t.TempDir()

	for i := 0; i < 5; i++ {
		f, _ := os.Create(filepath.Join(dir, "test"+string(rune('a'+i))+".log"))
		f.Close()
	}

	rotateLogFiles(dir, 3)

	entries, _ := os.ReadDir(dir)
	var logCount int
	for _, e := range entries {
		if !e.IsDir() {
			logCount++
		}
	}
	if logCount > 2 {
		t.Errorf("expected at most 2 log files after rotation (max=3 means rotate when >=3), got %d", logCount)
	}
}

func TestRotateLogFilesPreservesNonLog(t *testing.T) {
	dir := t.TempDir()

	f1, _ := os.Create(filepath.Join(dir, "test.log"))
	f1.Close()
	f2, _ := os.Create(filepath.Join(dir, "data.txt"))
	f2.Close()

	rotateLogFiles(dir, 1)

	if _, err := os.Stat(filepath.Join(dir, "data.txt")); os.IsNotExist(err) {
		t.Error("non-log file should not be deleted")
	}
}

func TestRotateLogFilesEmptyDir(t *testing.T) {
	dir := t.TempDir()
	rotateLogFiles(dir, 20)
}

func TestSetupNoFile(t *testing.T) {
	cleanup := Setup(false, slog.LevelWarn)
	defer cleanup()
}

func TestSetupVerbose(t *testing.T) {
	cleanup := Setup(false, slog.LevelInfo)
	defer cleanup()
}
