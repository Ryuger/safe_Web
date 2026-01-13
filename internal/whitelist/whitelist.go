package whitelist

import (
	"bufio"
	"errors"
	"net"
	"os"
	"strings"
)

type List struct {
	nets []*net.IPNet
}

func Load(path string) (*List, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var nets []*net.IPNet
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "/") {
			_, cidr, err := net.ParseCIDR(line)
			if err != nil {
				return nil, err
			}
			nets = append(nets, cidr)
			continue
		}

		ip := net.ParseIP(line)
		if ip == nil {
			return nil, errors.New("invalid ip in whitelist")
		}
		maskBits := 32
		if ip.To4() == nil {
			maskBits = 128
		}
		cidr := &net.IPNet{IP: ip, Mask: net.CIDRMask(maskBits, maskBits)}
		nets = append(nets, cidr)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &List{nets: nets}, nil
}

func (l *List) Allowed(ip net.IP) bool {
	if l == nil {
		return false
	}
	for _, cidr := range l.nets {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
