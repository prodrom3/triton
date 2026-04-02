// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package geo

import "net"

func parseIP(ip string) net.IP {
	return net.ParseIP(ip)
}
