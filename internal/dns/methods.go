package dns

import (
	"fmt"
	"strings"
)

func (pp *ParsedPacket) String() string {
	var b strings.Builder

	ipVer := "unknown"
	srcIP := ""
	dstIP := ""

	if pp.IPv4 != nil {
		ipVer = "IPv4"
		srcIP = pp.IPv4.SrcIP.String()
		dstIP = pp.IPv4.DstIP.String()
	} else if pp.IPv6 != nil {
		ipVer = "IPv6"
		srcIP = pp.IPv6.SrcIP.String()
		dstIP = pp.IPv6.DstIP.String()
	}

	write := func(k, v string) {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		fmt.Fprintf(&b, "\"%s\"", v)
	}

	write("ip", ipVer)
	write("src", srcIP)
	write("dst", dstIP)
	write("request", fmt.Sprint(pp.IsRequest))

	if pp.DNS != nil {
		if len(pp.DNS.Answers) > 0 {
			a := pp.DNS.Answers[0]
			write("dns_name", string(a.Name))
			write("dns_record", a.Type.String())
			write("dns_ttl", fmt.Sprint(a.TTL))
			write("dns_data", a.String())
		} else if len(pp.DNS.Questions) > 0 {
			q := pp.DNS.Questions[0]
			write("dns_name", string(q.Name))
			write("dns_record", q.Type.String())
			write("dns_class", q.Class.String())
		}
	}

	return b.String()
}

func (pp *ParsedPacket) LogFields() []any {
	fields := []any{
		"request", pp.IsRequest,
	}

	if pp.IPv4 != nil {
		fields = append(fields,
			"ip", "IPv4",
			"src", pp.IPv4.SrcIP.String(),
			"dst", pp.IPv4.DstIP.String(),
		)
	} else if pp.IPv6 != nil {
		fields = append(fields,
			"ip", "IPv6",
			"src", pp.IPv6.SrcIP.String(),
			"dst", pp.IPv6.DstIP.String(),
		)
	}

	if pp.DNS != nil {
		if len(pp.DNS.Answers) > 0 {
			a := pp.DNS.Answers[0]
			fields = append(fields,
				"dns_name", string(a.Name),
				"dns_record", a.Type.String(),
				"dns_ttl", a.TTL,
				"dns_data", a.String(),
			)
		} else if len(pp.DNS.Questions) > 0 {
			q := pp.DNS.Questions[0]
			fields = append(fields,
				"dns_name", string(q.Name),
				"dns_record", q.Type.String(),
				"dns_class", q.Class.String(),
			)
		}
	}

	return fields
}
