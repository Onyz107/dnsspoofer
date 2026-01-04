package dns

import (
	"fmt"
	"net"

	"github.com/google/gopacket/layers"
)

func buildDNSResponse(dnsLayer *layers.DNS, ips ...net.IP) (*layers.DNS, error) {
	var ipv4, ipv6 net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4 = ip
		} else if ip.To16() != nil {
			ipv6 = ip
		}
	}

	for i := range dnsLayer.Answers {
		a := &dnsLayer.Answers[i]

		switch a.Type {
		case layers.DNSTypeA:
			ip := ipv4.To4()
			if ip == nil {
				continue
			}
			a.IP = ip
			a.TTL = TTL

		case layers.DNSTypeAAAA:
			ip := ipv6.To16()
			if ip == nil {
				continue
			}
			a.IP = ip
			a.TTL = TTL
		}
	}

	if len(dnsLayer.Answers) > 0 {
		fmt.Print("return")
		return dnsLayer, nil
	}
	fmt.Print("no answers")

	var answers []layers.DNSResourceRecord
	for _, q := range dnsLayer.Questions {
		switch q.Type {
		case layers.DNSTypeA:
			if ipv4 == nil {
				continue
			}
			answers = append(answers, newARecord(q, ipv4))

		case layers.DNSTypeAAAA:
			if ipv6 == nil {
				continue
			}
			answers = append(answers, newAAAARecord(q, ipv6))
		}
	}

	return &layers.DNS{
		ID:           dnsLayer.ID,
		QR:           true,
		OpCode:       dnsLayer.OpCode,
		AA:           true,
		RD:           dnsLayer.RD,
		RA:           true,
		TC:           dnsLayer.TC,
		Z:            dnsLayer.Z,
		ResponseCode: layers.DNSResponseCodeNoErr,

		QDCount: uint16(len(dnsLayer.Questions)),
		ANCount: uint16(len(answers)),

		Questions: dnsLayer.Questions,
		Answers:   answers,
	}, nil
}

func newARecord(q layers.DNSQuestion, ip net.IP) layers.DNSResourceRecord {
	return layers.DNSResourceRecord{
		Name:  q.Name,
		Type:  layers.DNSTypeA,
		Class: q.Class,
		TTL:   TTL,
		IP:    ip,
	}
}

func newAAAARecord(q layers.DNSQuestion, ip net.IP) layers.DNSResourceRecord {
	return layers.DNSResourceRecord{
		Name:  q.Name,
		Type:  layers.DNSTypeAAAA,
		Class: q.Class,
		TTL:   TTL,
		IP:    ip,
	}
}
