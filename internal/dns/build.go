package dns

import (
	"net"

	"github.com/google/gopacket/layers"
)

// spoofAnswers modifies the IP addresses in the provided DNS answer records.
//
// Works only on passive mode.
func spoofAnswers(answers []layers.DNSResourceRecord, ips ...net.IP) []layers.DNSResourceRecord {
	var ipv4, ipv6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip)
		} else if ip.To16() != nil {
			ipv6 = append(ipv6, ip)
		}
	}

	for i := range answers {
		a := &answers[i]

		switch a.Type {
		case layers.DNSTypeA:
			if len(ipv4) <= i {
				i = len(ipv4) - 1
			}
			a.IP = ipv4[i]
			a.TTL = TTL

		case layers.DNSTypeAAAA:
			if len(ipv6) <= i {
				i = len(ipv6) - 1
			}
			a.IP = ipv6[i]
			a.TTL = TTL
		}
	}

	return answers
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

// answerDNSQuestions creates DNS answer records based on the provided questions and IPs.
//
// Works only on aggressive mode.
func answerDNSQuestions(questions []layers.DNSQuestion, ips ...net.IP) []layers.DNSResourceRecord {
	var answers []layers.DNSResourceRecord
	var ipv4, ipv6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip)
		} else if ip.To16() != nil {
			ipv6 = append(ipv6, ip)
		}
	}

	for _, q := range questions {
		switch q.Type {
		case layers.DNSTypeA:
			for _, ip := range ipv4 {
				answers = append(answers, newARecord(q, ip))
			}

		case layers.DNSTypeAAAA:
			for _, ip := range ipv6 {
				answers = append(answers, newAAAARecord(q, ip))
			}
		}

	}

	return answers
}

func buildDNSResponse(dnsLayer *layers.DNS, ips ...net.IP) (*layers.DNS, error) {
	if len(dnsLayer.Answers) > 0 {
		dnsLayer.Answers = spoofAnswers(dnsLayer.Answers, ips...)
		return dnsLayer, nil
	} else {
		answers := answerDNSQuestions(dnsLayer.Questions, ips...)
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
}
