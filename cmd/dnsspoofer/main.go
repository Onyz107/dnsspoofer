package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/Onyz107/dnsspoofer"
	"github.com/Onyz107/dnsspoofer/internal/banner"
	"github.com/Onyz107/dnsspoofer/internal/logger"
	"github.com/Onyz107/dnsspoofer/internal/wildhosts"
	"github.com/charmbracelet/log"
	"github.com/urfave/cli/v2"
)

const version = "1.3.3"

type options struct {
	Interface    string
	IPModeStr    string
	SpoofModeStr string
	ScopeStr     string
	Hosts        cli.Path
	QueueInt     int
	Debug        bool
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
			&cli.BoolFlag{
				Name:        "debug",
				Aliases:     []string{"d"},
				Usage:       "Enable debug logging",
				Value:       false,
				Destination: &opts.Debug,
			},
		},
		Action: func(c *cli.Context) error {
			if opts.Debug {
				logger.Log.SetLevel(log.DebugLevel)
				logger.Log.Debug("debugging on")
			}

			ifaceHandle, err := net.InterfaceByName(opts.Interface)
			if err != nil {
				return errors.Join(ErrOpenInterface, err)
			}

			var ipMode dnsspoofer.IPMode
			switch opts.IPModeStr {
			case "ipv4":
				ipMode = dnsspoofer.IPv4Only
			case "ipv6":
				ipMode = dnsspoofer.IPv6Only
			case "ipv4+ipv6":
				ipMode = dnsspoofer.IPv4AndIPv6
			default:
				return ErrInvalidIPMode
			}

			var spoofMode dnsspoofer.SpoofMode
			switch opts.SpoofModeStr {
			case "aggressive":
				spoofMode = dnsspoofer.Aggressive
			case "passive":
				spoofMode = dnsspoofer.Passive
			default:
				return ErrInvalidSpoofMode
			}

			var scope dnsspoofer.Scope
			switch opts.ScopeStr {
			case "local":
				scope = dnsspoofer.Local
			case "remote":
				scope = dnsspoofer.Remote
			default:
				return ErrInvalidScope
			}

			queue := uint16(opts.QueueInt)

			hosts, err := wildhosts.LoadFile(context.TODO(), opts.Hosts)
			if err != nil {
				return errors.Join(ErrLoadHostsFile, err)
			}
			hostsMap := hosts.Map()
			logger.Log.Debug("loaded hosts file", "map", hostsMap)

			sigCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			spoof := dnsspoofer.New(&dnsspoofer.EngineOptions{
				Iface:     ifaceHandle,
				IPMode:    ipMode,
				SpoofMode: spoofMode,
				Scope:     scope,
				Hosts:     hostsMap,
				Queue:     queue,
				Log:       logger.Log,
			})

			logger.Log.Info("starting dnsspoofer")
			if err := spoof.Run(sigCtx); err != nil {
				return errors.Join(ErrRunEngine, err)
			}

			<-sigCtx.Done()
			logger.Log.Info("shutting down dnsspoofer")
			spoof.Stop()

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		logger.Log.Fatal(err)
	}
}
