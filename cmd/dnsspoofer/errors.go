package main

import "errors"

var (
	ErrOpenInterface    = errors.New("failed to open network interface")
	ErrInvalidIPMode    = errors.New("invalid IP mode")
	ErrInvalidSpoofMode = errors.New("invalid spoof mode")
	ErrInvalidScope     = errors.New("invalid scope")
	ErrRedirectDNS      = errors.New("failed to redirect DNS to NFQUEUE")
	ErrLoadHostsFile    = errors.New("failed to load hosts file")
	ErrSpoofDNS         = errors.New("failed to spoof DNS")
)
