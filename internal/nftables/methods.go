package nftables

func (m *IPMode) String() string {
	switch *m {
	case IPv4Only:
		return "ipv4"
	case IPv6Only:
		return "ipv6"
	case IPv4AndIPv6:
		return "ipv4+ipv6"
	default:
		return "unknown"
	}
}

func (m *SpoofMode) String() string {
	switch *m {
	case Aggressive:
		return "aggressive"
	case Passive:
		return "passive"
	default:
		return "unknown"
	}
}

func (s *Scope) String() string {
	switch *s {
	case Local:
		return "local"
	case Remote:
		return "remote"
	default:
		return "unknown"
	}
}
