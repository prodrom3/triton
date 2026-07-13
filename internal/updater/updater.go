// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
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

// NeedsUpdate reports whether latest is a strictly newer release than current.
// Development builds ("dev") are never auto-updated. Using a numeric semver
// comparison (rather than string inequality) prevents downgrade: a re-tagged
// older release is not treated as an update.
func NeedsUpdate(current, latest string) bool {
	if strings.TrimPrefix(current, "v") == "dev" {
		return false
	}
	return compareSemver(latest, current) > 0
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
	assets := indexAssets(release.Assets)

	downloadURL := assets[assetName]
	if downloadURL == "" {
		return fmt.Errorf("no release asset found for %s/%s (expected %s)", runtime.GOOS, runtime.GOARCH, assetName)
	}
	sumsURL := assets[checksumsAsset]
	if sumsURL == "" {
		return fmt.Errorf("release is missing %s; refusing to install an unverifiable binary", checksumsAsset)
	}

	// Fetch and verify the checksum manifest before trusting any binary.
	sumsData, err := download(client, sumsURL, 1*1024*1024)
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", checksumsAsset, err)
	}

	if signatureConfigured() {
		sigURL := assets[checksumsSigAsset]
		if sigURL == "" {
			return fmt.Errorf("release is missing %s; refusing to install without a valid signature", checksumsSigAsset)
		}
		sigData, err := download(client, sigURL, 64*1024)
		if err != nil {
			return fmt.Errorf("failed to download %s: %w", checksumsSigAsset, err)
		}
		if err := verifyChecksumsSignature(sumsData, sigData); err != nil {
			return fmt.Errorf("release signature verification failed: %w", err)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Warning: release signature verification is not configured; verifying checksum only.")
	}

	wantSum, err := checksumFor(sumsData, assetName)
	if err != nil {
		return fmt.Errorf("checksum manifest error: %w", err)
	}

	fmt.Printf("Downloading %s ...\n", assetName)

	archiveData, err := download(client, downloadURL, 100*1024*1024)
	if err != nil {
		return fmt.Errorf("failed to download release: %w", err)
	}

	if err := verifyAsset(archiveData, wantSum); err != nil {
		return fmt.Errorf("downloaded asset failed verification: %w", err)
	}

	// Extract the binary from the verified archive.
	binaryData, err := extractBinary(bytes.NewReader(archiveData), assetName)
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

// indexAssets maps release asset names to their download URLs.
func indexAssets(assets []ghAsset) map[string]string {
	m := make(map[string]string, len(assets))
	for _, a := range assets {
		m[a.Name] = a.BrowserDownloadURL
	}
	return m
}

// download fetches a URL into memory, capping the read at maxBytes to bound
// memory use against oversized or malicious responses.
func download(client *http.Client, url string, maxBytes int64) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("returned status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, err
	}
	return data, nil
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
			return readCapped(tr, maxBinarySize)
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
			return readCapped(rc, maxBinarySize)
		}
	}
	return nil, fmt.Errorf("binary %q not found in archive", binName)
}

// maxBinarySize bounds the decompressed size of an extracted binary, both to
// limit memory against a decompression bomb and to detect truncation.
const maxBinarySize = 100 * 1024 * 1024

// readCapped reads all of r but fails if the content exceeds max, rather than
// silently truncating (which would install a corrupt binary).
func readCapped(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("extracted binary exceeds %d bytes; refusing to install a truncated file", max)
	}
	return data, nil
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

// CleanupStale removes leftover files from a previous update. On Windows the
// running binary is renamed to "<exe>.old" during an update and cannot be
// deleted until the process exits, so this best-effort cleanup runs at startup.
func CleanupStale() {
	if runtime.GOOS != "windows" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	_ = os.Remove(exe + ".old")
}
