package dns

import "errors"

var (
	ErrNoQuestions        = errors.New("dns packet has no questions")
	ErrInvalidAnswers     = errors.New("no valid answers")
	ErrInvalidIPVersion   = errors.New("invalid IP version")
	ErrInvalidIPLayer     = errors.New("invalid IP layer")
	ErrInvalidUDPLayer    = errors.New("invalid UDP layer")
	ErrInvalidDNSLayer    = errors.New("invalid DNS layer")
	ErrBuildDNSResponse   = errors.New("failed to build DNS response")
	ErrInvalidDNSRequest  = errors.New("invalid DNS request")
	ErrInvalidDNSResponse = errors.New("invalid DNS response")
	ErrSerializeLayers    = errors.New("failed to serialize layers")
)
