// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	repoOwner   = "prodrom3"
	repoName    = "triton"
	apiBase     = "https://api.github.com"
	binaryName  = "triton"
	httpTimeout = 30 * time.Second
)

// ghRelease is a subset of the GitHub release API response.
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// CheckLatest queries GitHub for the latest release tag.
// Returns the tag (e.g. "v1.2.0" or "1.2.0") and nil on success.
func CheckLatest() (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases/latest", apiBase, repoOwner, repoName)

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to check for updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("no releases found")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("failed to parse release info: %w", err)
	}

	return release.TagName, nil
}

// NeedsUpdate compares current version against the latest release tag.
func NeedsUpdate(current, latest string) bool {
	c := strings.TrimPrefix(current, "v")
	l := strings.TrimPrefix(latest, "v")
	return c != l && c != "dev"
}

// Update downloads the latest release binary and replaces the current executable.
func Update(currentVersion string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/releases/latest", apiBase, repoOwner, repoName)

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch release info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("failed to parse release info: %w", err)
	}

	if !NeedsUpdate(currentVersion, release.TagName) {
		fmt.Printf("Already up to date (%s)\n", currentVersion)
		return nil
	}

	assetName := expectedAssetName(release.TagName)
	var downloadURL string
	for _, a := range release.Assets {
		if a.Name == assetName {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		return fmt.Errorf("no release asset found for %s/%s (expected %s)", runtime.GOOS, runtime.GOARCH, assetName)
	}

	fmt.Printf("Downloading %s ...\n", assetName)

	archiveResp, err := client.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download release: %w", err)
	}
	defer archiveResp.Body.Close()

	if archiveResp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %d", archiveResp.StatusCode)
	}

	// Extract the binary from the archive
	binaryData, err := extractBinary(archiveResp.Body, assetName)
	if err != nil {
		return fmt.Errorf("failed to extract binary: %w", err)
	}

	// Replace the current executable
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	if err := replaceBinary(execPath, binaryData); err != nil {
		return err
	}

	fmt.Printf("Updated triton %s -> %s\n", currentVersion, release.TagName)
	return nil
}

func expectedAssetName(tag string) string {
	ver := strings.TrimPrefix(tag, "v")
	osName := runtime.GOOS
	arch := runtime.GOARCH
	ext := "tar.gz"
	if runtime.GOOS == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("%s_%s_%s_%s.%s", binaryName, ver, osName, arch, ext)
}

func extractBinary(r io.Reader, assetName string) ([]byte, error) {
	binName := binaryName
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}

	if strings.HasSuffix(assetName, ".zip") {
		return extractFromZip(r, binName)
	}
	return extractFromTarGz(r, binName)
}

func extractFromTarGz(r io.Reader, binName string) ([]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("gzip error: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar error: %w", err)
		}
		if filepath.Base(header.Name) == binName && header.Typeflag == tar.TypeReg {
			data, err := io.ReadAll(io.LimitReader(tr, 100*1024*1024)) // 100MB cap
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("binary %q not found in archive", binName)
}

func extractFromZip(r io.Reader, binName string) ([]byte, error) {
	// zip requires random access, so buffer to a temp file
	tmp, err := os.CreateTemp("", "triton-update-*.zip")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if _, err := io.Copy(tmp, io.LimitReader(r, 100*1024*1024)); err != nil {
		return nil, err
	}

	fi, err := tmp.Stat()
	if err != nil {
		return nil, err
	}

	zr, err := zip.NewReader(tmp, fi.Size())
	if err != nil {
		return nil, fmt.Errorf("zip error: %w", err)
	}

	for _, f := range zr.File {
		if filepath.Base(f.Name) == binName {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("binary %q not found in archive", binName)
}

// replaceBinary atomically replaces the executable at path.
// On Windows, the running binary cannot be overwritten directly,
// so the old file is renamed first.
func replaceBinary(path string, data []byte) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	// Write new binary to a temp file in the same directory
	tmp, err := os.CreateTemp(dir, base+".update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write new binary: %w", err)
	}
	tmp.Close()

	// Make executable on Unix
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpPath, 0755); err != nil {
			os.Remove(tmpPath)
			return err
		}
	}

	// On Windows, rename the running binary out of the way first
	if runtime.GOOS == "windows" {
		oldPath := path + ".old"
		os.Remove(oldPath) // clean up any previous .old file
		if err := os.Rename(path, oldPath); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("failed to move old binary: %w", err)
		}
	}

	// Move new binary into place
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	return nil
}
