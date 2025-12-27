package spoof

import "errors"

var ErrOpenNFQUEUE = errors.New("failed to open NFQUEUE")
var ErrGetNFQUEUEChan = errors.New("failed to get NFQUEUE packet channel")
var ErrParsePacket = errors.New("failed to parse packet")
var ErrSpoofPacket = errors.New("failed to spoof packet")
var ErrInvalidIPVersion = errors.New("invalid IP version")
var ErrSerializeLayers = errors.New("failed to serialize layers")
var ErrSerializePacket = errors.New("failed to serialize packet")
var ErrSetVerdict = errors.New("failed to set packet verdict")
