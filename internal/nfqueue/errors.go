package nfqueue

import "errors"

var ErrOpenNFQUEUE = errors.New("failed to open NFQUEUE")
var ErrRegisterFunc = errors.New("failed to register function to NFQUEUE")
var ErrNFQUEUERead = errors.New("nfqueue failed to read packets")
