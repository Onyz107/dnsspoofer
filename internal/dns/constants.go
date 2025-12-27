package dns

import "github.com/google/gopacket/layers"

const TTL = 60

type ParsedPacket struct {
	IPv4 *layers.IPv4
	IPv6 *layers.IPv6
	UDP  *layers.UDP
	DNS  *layers.DNS

	Name      string
	Record    string
	IPVersion uint32
	IsRequest bool
}
