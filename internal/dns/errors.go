package dns

import "errors"

var ErrNoQuestions = errors.New("dns packet has no questions")
var ErrInvalidAnswers = errors.New("no valid answers")
var ErrInvalidIPVersion = errors.New("invalid IP version")
var ErrInvalidIPLayer = errors.New("invalid IP layer")
var ErrInvalidUDPLayer = errors.New("invalid UDP layer")
var ErrInvalidDNSLayer = errors.New("invalid DNS layer")
var ErrBuildDNSResponse = errors.New("failed to build DNS response")
var ErrInvalidDNSRequest = errors.New("invalid DNS request")
var ErrInvalidDNSResponse = errors.New("invalid DNS response")
