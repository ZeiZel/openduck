package providerbridge

import "errors"

var (
	ErrUnknownProvider        = errors.New("providerbridge: unknown provider")
	ErrUnknownProfile         = errors.New("providerbridge: unknown profile")
	ErrProfileIncompatible    = errors.New("providerbridge: profile incompatible")
	ErrEvidenceInvalid        = errors.New("providerbridge: evidence invalid")
	ErrEvidenceDigestMismatch = errors.New("providerbridge: evidence digest mismatch")
	ErrEvidenceStale          = errors.New("providerbridge: evidence stale")
	ErrEvidenceUntrusted      = errors.New("providerbridge: evidence untrusted")
	ErrLimitsMissing          = errors.New("providerbridge: finite execution limits required")
	ErrMappingMissing         = errors.New("providerbridge: verified mapping required")
	ErrBindingInvalid         = errors.New("providerbridge: endpoint binding invalid")
	ErrCompatibilityInvalid   = errors.New("providerbridge: compatibility record invalid")
)
