package dnsspoofer

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/Onyz107/dnsspoofer/internal/dns"
	"github.com/Onyz107/dnsspoofer/internal/logger"
	"github.com/Onyz107/dnsspoofer/internal/nfqueue"
	"github.com/Onyz107/dnsspoofer/internal/nftables"
	gonfqueue "github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"
)

func New(opts *EngineOptions) *Engine {
	if opts.Log == nil {
		opts.Log = new(logger.NopLogger)
	}
	engine := &Engine{
		opts: opts,
	}
	return engine
}

func (e *Engine) Run(ctx context.Context) error {
	inCtx, cancel := context.WithCancel(ctx)
	e.ctx = logger.WithLogger(inCtx, e.opts.Log)
	e.cancel = cancel

	clean, err := nftables.AddDNSQueue(e.ctx, e.opts.IPMode, e.opts.Iface, e.opts.SpoofMode, e.opts.Scope, e.opts.Queue)
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
		Logger:       e.opts.Log,
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

	pkts, err := nfqueue.GetPacketChan(e.ctx, nfq)
	if err != nil {
		return errors.Join(ErrGetPacketChan, err)
	}

	for {
		select {
		case <-e.ctx.Done():
			return nil
		case pkt := <-pkts:
			parsed, err := dns.ParsePacket(e.ctx, pkt)
			if err != nil {
				e.opts.Log.Error(ErrParsePacket.Error(), "err", err)
				nfq.SetVerdict(pkt.PacketID, gonfqueue.NfAccept)
				continue
			}
			e.opts.Log.Info("parsed packet", parsed.LogFields()...)

			var name string
			if len(parsed.DNS.Answers) > 0 {
				name = string(parsed.DNS.Answers[0].Name)
			} else if len(parsed.DNS.Questions) > 0 {
				name = string(parsed.DNS.Questions[0].Name)
			}
			name = strings.ToLower(strings.TrimSuffix(name, "."))

			var ips []net.IP
			for re, ipaddrs := range e.opts.Hosts {
				if re.MatchString(name) {
					ips = ipaddrs // Use the last matching entry
				}
			}
			if len(ips) == 0 {
				logger.Log.Info("parsed packet not in whitelist, skipping")
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
				e.opts.Log.Error(ErrSpoofPacket.Error(), "err", err)
				nfq.SetVerdict(pkt.PacketID, gonfqueue.NfAccept)
				continue
			}
			e.opts.Log.Info("spoofed packet", spoofed.LogFields()...)

			newBytes, err := spoofed.Serialize()
			if err != nil {
				e.opts.Log.Error(ErrSerializePkt.Error(), "err", err)
				nfq.SetVerdict(pkt.PacketID, gonfqueue.NfAccept)
				continue
			}

			if err := nfq.SetVerdictWithOption(pkt.PacketID, gonfqueue.NfAccept, gonfqueue.WithAlteredPacket(newBytes)); err != nil {
				e.opts.Log.Error(ErrSetVerdict.Error(), "err", err)
				nfq.SetVerdict(pkt.PacketID, gonfqueue.NfAccept)
			}
		}
	}
}

func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
}
