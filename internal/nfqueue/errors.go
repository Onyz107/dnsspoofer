package nfqueue

import "errors"

var (
	ErrOpenNFQUEUE  = errors.New("failed to open NFQUEUE")
	ErrRegisterFunc = errors.New("failed to register function to NFQUEUE")
	ErrNFQUEUERead  = errors.New("nfqueue failed to read packets")
)
