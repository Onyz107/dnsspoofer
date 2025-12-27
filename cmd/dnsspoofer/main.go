package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/Onyz107/dnsspoofer/internal/banner"
	"github.com/Onyz107/dnsspoofer/internal/logger"
	"github.com/Onyz107/dnsspoofer/internal/nftables"
	"github.com/Onyz107/dnsspoofer/internal/wildhosts"
	"github.com/Onyz107/dnsspoofer/redirect"
	"github.com/Onyz107/dnsspoofer/spoof"
	"github.com/urfave/cli/v2"
)

const version = "1.0.0"

type options struct {
	Interface    string
	IPModeStr    string
	SpoofModeStr string
	ScopeStr     string
	Hosts        cli.Path
	QueueInt     int
}

func main() {
	banner.PrintBanner("DNSspoofer", version)

	opts := &options{}

	app := &cli.App{
		Name:    os.Args[0],
		Usage:   "A reliable DNS spoofer",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "interface",
				Aliases:     []string{"i"},
				Usage:       "Network interface to use",
				Required:    true,
				Destination: &opts.Interface,
			},
			&cli.StringFlag{
				Name:        "ip-mode",
				Aliases:     []string{"im"},
				Usage:       "IP stack to spoof: ipv4 (ARP) (A), ipv6 (NDP) (AAAA), ipv4+ipv6",
				Value:       "ipv4+ipv6",
				Destination: &opts.IPModeStr,
			},
			&cli.StringFlag{
				Name:        "spoof-mode",
				Aliases:     []string{"sm"},
				Usage:       "Spoofing behavior: aggressive (reply to requests) or passive (modify responses)",
				Value:       "passive",
				Destination: &opts.SpoofModeStr,
			},
			&cli.PathFlag{
				Name:        "hosts",
				Usage:       "Path to a hosts(5) formatted file, one hostname per line, wildcards allowed.",
				Required:    true,
				Destination: &opts.Hosts,
			},
			&cli.StringFlag{
				Name:        "scope",
				Aliases:     []string{"s"},
				Usage:       "Packet scope: local (OUTPUT, this machine) or remote (FORWARD, router/MITM)",
				Value:       "remote",
				Destination: &opts.ScopeStr,
			},
			&cli.IntFlag{
				Name:        "queue",
				Aliases:     []string{"q"},
				Usage:       "NFQUEUE number to bind to",
				Value:       0,
				Destination: &opts.QueueInt,
			},
		},
		Action: func(c *cli.Context) error {
			ifaceHandle, err := net.InterfaceByName(opts.Interface)
			if err != nil {
				return errors.Join(ErrOpenInterface, err)
			}

			var ipMode nftables.IPMode
			switch opts.IPModeStr {
			case "ipv4":
				ipMode = nftables.IPv4Only
			case "ipv6":
				ipMode = nftables.IPv6Only
			case "ipv4+ipv6":
				ipMode = nftables.IPv4AndIPv6
			default:
				return ErrInvalidIPMode
			}

			var spoofMode nftables.SpoofMode
			switch opts.SpoofModeStr {
			case "aggressive":
				spoofMode = nftables.Aggressive
			case "passive":
				spoofMode = nftables.Passive
			default:
				return ErrInvalidSpoofMode
			}

			var scope nftables.Scope
			switch opts.ScopeStr {
			case "local":
				scope = nftables.Local
			case "remote":
				scope = nftables.Remote
			default:
				return ErrInvalidScope
			}

			queue := uint16(opts.QueueInt)

			sigCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			cleanup, err := redirect.DNS(ipMode, ifaceHandle, spoofMode, scope, uint16(queue))
			if err != nil {
				return errors.Join(ErrRedirectDNS, err)
			}
			defer cleanup()

			hosts, err := wildhosts.LoadFile(opts.Hosts)
			if err != nil {
				return errors.Join(ErrLoadHostsFile, err)
			}

			if err := spoof.DNS(sigCtx, queue, hosts); err != nil {
				return errors.Join(ErrSpoofDNS, err)
			}

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		logger.Logger.Fatal(err)
	}
}
