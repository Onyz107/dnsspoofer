package dns

import (
	"context"
	"fmt"

	"github.com/Onyz107/dnsspoofer/internal/logger"
	"github.com/Onyz107/dnsspoofer/internal/nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func ParsePacket(ctx context.Context, pkt nfqueue.Packet) (*ParsedPacket, error) {
	log := logger.LoggerFrom(ctx)

	var packet gopacket.Packet
	var ipLayer gopacket.Layer
	ipVersion := pkt.IPVersion
	switch ipVersion {
	case 4:
		packet = gopacket.NewPacket(pkt.Payload, layers.LayerTypeIPv4, gopacket.Lazy)
		ipLayer = packet.Layer(layers.LayerTypeIPv4)
	case 6:
		packet = gopacket.NewPacket(pkt.Payload, layers.LayerTypeIPv6, gopacket.Lazy)
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
	default:
		return nil, fmt.Errorf("%w: %d", ErrInvalidIPVersion, ipVersion)
	}

	if ipLayer == nil {
		log.Debug("malformed IP layer", "payload", pkt.Payload)
		return nil, ErrInvalidIPLayer
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		log.Debug("malformed UDP layer", "payload", pkt.Payload)
		return nil, ErrInvalidUDPLayer
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		log.Debug("malformed DNS layer", "payload", pkt.Payload)
		return nil, ErrInvalidDNSLayer
	}

	var ipv4 *layers.IPv4
	var ipv6 *layers.IPv6
	udp := udpLayer.(*layers.UDP)
	dns := dnsLayer.(*layers.DNS)
	if len(dns.Questions) == 0 {
		log.Debug("malformed DNS layer", "payload", pkt.Payload)
		return nil, ErrInvalidDNSLayer
	}
	switch ipVersion {
	case 4:
		ipv4 = ipLayer.(*layers.IPv4)
		udp.SetNetworkLayerForChecksum(ipv4)
	case 6:
		ipv6 = ipLayer.(*layers.IPv6)
		udp.SetNetworkLayerForChecksum(ipv6)
	default:
		return nil, fmt.Errorf("%w: %d", ErrInvalidIPVersion, ipVersion)
	}

	firstQuestion := dns.Questions[0]
	parsedPkt := &ParsedPacket{
		IPv4: ipv4,
		IPv6: ipv6,
		UDP:  udp,
		DNS:  dns,

		Name:      string(firstQuestion.Name),
		Record:    firstQuestion.Type.String(),
		IPVersion: ipVersion,
		IsRequest: !dns.QR,
	}

	return parsedPkt, nil
}
