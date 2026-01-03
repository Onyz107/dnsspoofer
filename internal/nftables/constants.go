package nftables

import "sync"

// IPMode determines the IP spoofing mode.
type IPMode uint32

// SpoofMode determines the DNS spoofing mode.
type SpoofMode uint32

// Scope determines the scope for DNS spoofing.
type Scope uint32

const (
	// IPv4Only only spoofs IPv4 DNS requests/responses (A records)
	IPv4Only IPMode = iota
	// IPv6Only only spoof IPv6 DNS requests/responses (AAAA records)
	IPv6Only
	// IPv4AndIPv6 spoos both IPv4 and IPv6 DNS requests/responses (A and AAAA records)
	IPv4AndIPv6
)

const (
	// Aggressive SpoofMode intercepts DNS requests and responds to them, then eventually drops the request.
	Aggressive SpoofMode = iota
	// Passive SpoofMode intercepts DNS responses and modifies them.
	Passive
)

const (
	// Local only spoofs packets coming from the local machine (OUTPUT chain)
	Local Scope = iota
	// Remote only spoofs packets coming from remote machines (FORWARD chanin)
	Remote
)

const (
	udpDestPortOffset   = 2
	udpSourcePortOffset = 0
)

var once sync.Once
