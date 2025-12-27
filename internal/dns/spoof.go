package dns

import (
	"errors"
	"net"
)

func SpoofRequest(pp *ParsedPacket, ips ...net.IP) (*ParsedPacket, error) {
	if pp.DNS == nil || !pp.IsRequest {
		return nil, ErrInvalidDNSRequest
	}

	if len(pp.DNS.Questions) == 0 {
		return nil, ErrNoQuestions
	}

	dnsRes, err := buildDNSResponse(pp.DNS, ips...)
	if err != nil {
		return nil, errors.Join(ErrBuildDNSResponse, err)
	}

	pp.UDP.SrcPort, pp.UDP.DstPort = pp.UDP.DstPort, pp.UDP.SrcPort

	switch pp.IPVersion {
	case 4:
		pp.IPv4.SrcIP, pp.IPv4.DstIP = pp.IPv4.DstIP, pp.IPv4.SrcIP

		pp.DNS = dnsRes
		pp.IsRequest = false

		return pp, nil

	case 6:
		pp.IPv6.SrcIP, pp.IPv6.DstIP = pp.IPv6.DstIP, pp.IPv6.SrcIP

		pp.DNS = dnsRes
		pp.IsRequest = false

		return pp, nil

	default:
		return nil, ErrInvalidIPVersion
	}
}

func SpoofResponse(pp *ParsedPacket, ips ...net.IP) (*ParsedPacket, error) {
	if pp.DNS == nil || pp.IsRequest {
		return nil, ErrInvalidDNSResponse
	}

	dnsRes, err := buildDNSResponse(pp.DNS, ips...)
	if err != nil {
		return nil, errors.Join(ErrBuildDNSResponse, err)
	}

	pp.DNS = dnsRes

	return pp, nil
}
