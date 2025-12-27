package wildhosts

import "errors"

var (
	ErrMissingHostnamePattern = errors.New("missing hostname pattern")
	ErrAlias                  = errors.New("aliases not allowed")
	ErrInvalidIP              = errors.New("invalid IP")
	ErrEmptyHostname          = errors.New("empty hostname pattern")
)
