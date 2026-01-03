package dnsspoofer

import "errors"

var (
	ErrAddDNSQueue   = errors.New("failed to add DNS NFQueue rules")
	ErrOpenNFQueue   = errors.New("failed to open NFQueue")
	ErrGetPacketChan = errors.New("failed to get NFQueue packet channel")
	ErrParsePacket   = errors.New("failed to parse DNS packet")
	ErrSpoofPacket   = errors.New("failed to spoof DNS packet")
	ErrSerializePkt  = errors.New("failed to serialize spoofed DNS packet")
	ErrSetVerdict    = errors.New("failed to set NFQueue packet verdict")
)
