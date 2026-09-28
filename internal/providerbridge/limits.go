package providerbridge

// Digest returns the canonical digest of the complete finite limits object.
// Callers must bind this exact value into Profile.ExecutionLimitsDigest.
func (l ExecutionLimits) Digest() (string, error) {
	if err := l.Validate(); err != nil {
		return "", err
	}
	return digest(l)
}

func (l ExecutionLimits) Validate() error {
	if l.SchemaVersion != ExecutionLimitsV1 || l.MaxDepth == 0 || l.MaxChildrenPerParent == 0 || l.MaxConcurrentRuns == 0 || l.MaxInputTokens == 0 || l.MaxOutputTokens == 0 || l.MaxWallMS == 0 || l.MaxAttempts == 0 || l.MaxResultBytes == 0 {
		return ErrLimitsMissing
	}
	for _, value := range []uint64{l.MaxDepth, l.MaxChildrenPerParent, l.MaxConcurrentRuns, l.MaxInputTokens, l.MaxOutputTokens, l.MaxWallMS, l.MaxAttempts, l.MaxResultBytes} {
		if value > uint64(^uint(0)>>1) {
			return ErrLimitsMissing
		}
	}
	switch l.Cost.Kind {
	case "monetary":
		if !validCurrency(l.Cost.Currency) || l.Cost.MinorUnitExponent > 3 || l.Cost.MaxMinorUnits == 0 || l.Cost.Unit != "" || l.Cost.MaxQuantity != 0 {
			return ErrLimitsMissing
		}
	case "non_monetary":
		if l.Cost.Currency != "" || l.Cost.MinorUnitExponent != 0 || l.Cost.MaxMinorUnits != 0 || (l.Cost.Unit != "request" && l.Cost.Unit != "token" && l.Cost.Unit != "compute_ms") || l.Cost.MaxQuantity == 0 {
			return ErrLimitsMissing
		}
	default:
		return ErrLimitsMissing
	}
	return nil
}

func validCurrency(value string) bool {
	if len(value) != 3 {
		return false
	}
	for _, r := range value {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}
