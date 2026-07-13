// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// File represents a .triton.yml / .triton.json configuration file.
// Uses JSON internally since Go stdlib supports it without dependencies.
// The file is named .triton.json for simplicity.
type File struct {
	DB             string   `json:"db,omitempty"`
	ASNDB          string   `json:"asn_db,omitempty"`
	MaxHops        *int     `json:"max_hops,omitempty"`
	Timeout        *float64 `json:"timeout,omitempty"`
	Workers        *int     `json:"workers,omitempty"`
	NoTraceroute   *bool    `json:"no_traceroute,omitempty"`
	Whois          *bool    `json:"whois,omitempty"`
	DnsAll         *bool    `json:"dns_all,omitempty"`
	Ports          string   `json:"ports,omitempty"`
	TLS            *bool    `json:"tls,omitempty"`
	AllIPs         *bool    `json:"all_ips,omitempty"`
	Ping           *bool    `json:"ping,omitempty"`
	HTTP           *bool    `json:"http,omitempty"`
	Verbose        *bool    `json:"verbose,omitempty"`
	Quiet          *bool    `json:"quiet,omitempty"`
	Log            *bool    `json:"log,omitempty"`
	Proxy          string   `json:"proxy,omitempty"`
	Rate           *float64 `json:"rate,omitempty"`
	Retries        *int     `json:"retries,omitempty"`
	NoPrivate      *bool    `json:"no_private,omitempty"`
	PingPort       *int     `json:"ping_port,omitempty"`
	CertExpiryDays *int     `json:"cert_expiry_days,omitempty"`
	Resolver       string   `json:"resolver,omitempty"`
	UserAgent      string   `json:"user_agent,omitempty"`
	Targets        []string `json:"targets,omitempty"`
}

// Load reads the configuration file. When explicitPath is non-empty, only that
// file is loaded and a read/parse failure is returned as an error. Otherwise
// the per-user config at $HOME/.triton.json is used if present.
//
// The current working directory is deliberately NOT searched: auto-loading a
// .triton.json from an untrusted directory would let that directory silently
// inject scan targets or redirect the GeoIP database path. Use --config to load
// a project-local file explicitly.
func Load(explicitPath string) (*File, error) {
	if explicitPath != "" {
		f, err := loadFile(explicitPath)
		if err != nil {
			return nil, err
		}
		return f, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}
	f, err := loadFile(filepath.Join(home, ".triton.json"))
	if err != nil {
		// Missing per-user config is not an error.
		return nil, nil
	}
	return f, nil
}

func loadFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &f, nil
}
