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
	DB           string   `json:"db,omitempty"`
	ASNDB        string   `json:"asn_db,omitempty"`
	MaxHops      *int     `json:"max_hops,omitempty"`
	Timeout      *float64 `json:"timeout,omitempty"`
	Workers      *int     `json:"workers,omitempty"`
	NoTraceroute *bool    `json:"no_traceroute,omitempty"`
	Whois        *bool    `json:"whois,omitempty"`
	DnsAll       *bool    `json:"dns_all,omitempty"`
	Ports        string   `json:"ports,omitempty"`
	TLS          *bool    `json:"tls,omitempty"`
	AllIPs       *bool    `json:"all_ips,omitempty"`
	Ping         *bool    `json:"ping,omitempty"`
	HTTP         *bool    `json:"http,omitempty"`
	Verbose      *bool    `json:"verbose,omitempty"`
	Quiet        *bool    `json:"quiet,omitempty"`
	Targets      []string `json:"targets,omitempty"`
}

// Load searches for a config file in the current directory and home directory.
// Returns nil if no config file is found (not an error).
func Load() *File {
	candidates := []string{
		".triton.json",
	}

	// Also check home directory
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".triton.json"))
	}

	for _, path := range candidates {
		f, err := loadFile(path)
		if err == nil {
			return f
		}
	}
	return nil
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
