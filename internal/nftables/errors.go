package nftables

import "errors"

var (
	ErrNewNetlinkConn       = errors.New("failed to create a new netlink connection")
	ErrFlush                = errors.New("failed to push nftables rules to kernel, try flushing nftables")
	ErrInvalidIPMode        = errors.New("invalid IP mode")
	ErrInvalidScope         = errors.New("invalid scope")
	ErrInvalidSpoofMode     = errors.New("invalid spoof mode")
	ErrUnkownIPModeValue    = errors.New("unknown IP mode value")
	ErrUnkownSpoofModeValue = errors.New("unknown spoof mode value")
	ErrUnkownScopeValue     = errors.New("unknown scope value")
)
