package nftables

import "errors"

var ErrNewNetlinkConn = errors.New("failed to create a new netlink connection")
var ErrFlush = errors.New("failed to push nftables rules to kernel, try flushing nftables")
var ErrInvalidIPMode = errors.New("invalid IP mode")
var ErrInvalidScope = errors.New("invalid scope")
var ErrInvalidSpoofMode = errors.New("invalid spoof mode")
var ErrUnkownIPModeValue = errors.New("unknown IP mode value")
var ErrUnkownSpoofModeValue = errors.New("unknown spoof mode value")
var ErrUnkownScopeValue = errors.New("unknown scope value")
