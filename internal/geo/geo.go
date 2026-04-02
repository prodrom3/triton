// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package geo

import (
	"net"

	"github.com/oschwald/geoip2-golang"
	"github.com/prodrom3/triton/internal/models"
)

// Reader wraps GeoLite2 city and ASN database readers.
// geoip2.Reader uses memory-mapped files and is safe for concurrent reads,
// so no mutex is needed here.
type Reader struct {
	cityReader   *geoip2.Reader
	asnReader    *geoip2.Reader
	Available    bool
	ASNAvailable bool
}

// NewReader creates a GeoIP reader from the given database paths.
func NewReader(cityDB, asnDB string) *Reader {
	r := &Reader{}

	if cityDB != "" {
		reader, err := geoip2.Open(cityDB)
		if err == nil {
			r.cityReader = reader
			r.Available = true
		}
	}

	if asnDB != "" {
		reader, err := geoip2.Open(asnDB)
		if err == nil {
			r.asnReader = reader
			r.ASNAvailable = true
		}
	}

	return r
}

// Close releases database resources.
func (r *Reader) Close() {
	if r.cityReader != nil {
		r.cityReader.Close()
	}
	if r.asnReader != nil {
		r.asnReader.Close()
	}
}

// Lookup returns geolocation data for a single IP.
// This method is safe for concurrent use - geoip2 uses mmap internally.
func (r *Reader) Lookup(ip string) models.GeoResult {
	parsedIP := parseIP(ip)
	if parsedIP == nil {
		return models.GeoResult{IP: ip, City: "Invalid IP", Country: "Invalid IP", Found: false}
	}

	if !r.Available {
		if r.ASNAvailable {
			return r.asnOnlyLookup(ip, parsedIP)
		}
		return models.GeoResult{IP: ip, City: "N/A", Country: "N/A", Found: false}
	}

	record, err := r.cityReader.City(parsedIP)
	if err != nil {
		return models.GeoResult{IP: ip, City: "Not Found", Country: "Not Found", Found: false}
	}

	city := record.City.Names["en"]
	if city == "" {
		city = "Unknown"
	}
	country := record.Country.Names["en"]
	if country == "" {
		country = "Unknown"
	}

	geo := models.GeoResult{
		IP:      ip,
		City:    city,
		Country: country,
		Found:   true,
	}

	if record.Location.Latitude != 0 || record.Location.Longitude != 0 {
		geo.Latitude = &record.Location.Latitude
		geo.Longitude = &record.Location.Longitude
	}

	if len(record.Subdivisions) > 0 {
		name := record.Subdivisions[0].Names["en"]
		if name != "" {
			geo.Region = &name
		}
	}

	if r.ASNAvailable && r.asnReader != nil {
		asnRecord, err := r.asnReader.ASN(parsedIP)
		if err == nil {
			geo.ASN = models.Ptr(int(asnRecord.AutonomousSystemNumber))
			if asnRecord.AutonomousSystemOrganization != "" {
				geo.ASNOrg = &asnRecord.AutonomousSystemOrganization
			}
		}
	}

	return geo
}

func (r *Reader) asnOnlyLookup(ip string, parsed net.IP) models.GeoResult {
	if r.asnReader == nil {
		return models.GeoResult{IP: ip, City: "N/A", Country: "N/A", Found: false}
	}
	asnRecord, err := r.asnReader.ASN(parsed)
	if err != nil {
		return models.GeoResult{IP: ip, City: "N/A", Country: "N/A", Found: false}
	}
	geo := models.GeoResult{
		IP:      ip,
		City:    "N/A",
		Country: "N/A",
		Found:   false,
		ASN:     models.Ptr(int(asnRecord.AutonomousSystemNumber)),
	}
	if asnRecord.AutonomousSystemOrganization != "" {
		geo.ASNOrg = &asnRecord.AutonomousSystemOrganization
	}
	return geo
}
