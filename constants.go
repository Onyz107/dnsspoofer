package dnsspoofer

import (
	"context"
	"net"
	"regexp"

	"github.com/Onyz107/dnsspoofer/internal/logger"
	"github.com/Onyz107/dnsspoofer/internal/nftables"
)

// IPMode determines the IP spoofing mode.
type IPMode = nftables.IPMode

// SpoofMode determines the DNS spoofing mode.
type SpoofMode = nftables.SpoofMode

// Scope determines the scope for DNS spoofing.
type Scope = nftables.Scope

// Logger is the logging interface used by the DNS spoofer engine
type Logger interface {
	logger.Logger
}

const (
	// IPv4Only only spoofs IPv4 DNS requests/responses (A records)
	IPv4Only = nftables.IPv4Only
	// IPv6Only only spoof IPv6 DNS requests/responses (AAAA records)
	IPv6Only = nftables.IPv6Only
	// IPv4AndIPv6 spoofs both IPv4 and IPv6 DNS requests/responses (A and AAAA records)
	IPv4AndIPv6 = nftables.IPv4AndIPv6
)

const (
	// Aggressive SpoofMode intercepts DNS requests and responds to them, then eventually drops the request.
	Aggressive = nftables.Aggressive
	// Passive SpoofMode intercepts DNS responses and modifies them.
	Passive = nftables.Passive
)

const (
	// Local only spoofs packets coming from the local machine (OUTPUT chain)
	Local = nftables.Local
	// Remote only spoofs packets coming from remote machines (FORWARD chain)
	Remote = nftables.Remote
)

// Engine is the main DNS spoofer engine
type Engine struct {
	// ctx is the context for the engine
	ctx context.Context
	// cancel is the cancel function for the context
	cancel context.CancelFunc
	// opts holds the configuration options
	opts *EngineOptions
}

// Hosts represents a mapping of hostnames to IP addresses
type Hosts map[*regexp.Regexp][]net.IP

// EngineOptions holds the configuration options for the DNS spoofer engine
type EngineOptions struct {
	// Iface is the network interface to use
	Iface *net.Interface
	// IPMode is the IP mode to use (IPv4, IPv6, or both)
	IPMode IPMode
	// SpoofMode is the spoofing mode to use (aggressive or passive)
	SpoofMode SpoofMode
	// Scope is the packet scope to use (local or remote)
	Scope Scope
	// Hosts is the mapping of hostnames to IP addresses
	Hosts Hosts
	// Queue is the NFQUEUE number to use
	Queue uint16
	// Log is the logger to use, if nil a dev/null logger is used
	Log Logger
}
