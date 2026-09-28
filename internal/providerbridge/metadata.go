package providerbridge

import (
	"net/url"
	"path"
	"strings"
	"unicode"
)

const (
	maxURLBytes       = 512
	maxReferenceBytes = 512
	maxMetadataBytes  = 256
)

func validSafeToken(value string, max int) bool {
	if value == "" || len(value) > max || containsSensitiveMetadata(value) {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._-/:@+", r)) {
			return false
		}
	}
	return true
}

func validSafeEvent(value string) bool { return validSafeToken(value, 256) }

func validDecisionReference(value string) bool {
	if strings.HasPrefix(value, "https://") {
		return validHTTPSURL(value)
	}
	return validSafeToken(value, maxMetadataBytes)
}

func containsSensitiveMetadata(value string) bool {
	lower := strings.ToLower(value)
	for _, forbidden := range []string{"password", "credential", "private_key", "client_secret", "access_key", "api_key", "token=", "secret=", "authorization=", "stdout", "stderr", "prompt"} {
		if strings.Contains(lower, forbidden) {
			return true
		}
	}
	for _, r := range value {
		if r <= 0x20 || r == 0x7f || unicode.IsSpace(r) || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func validHTTPSURL(value string) bool {
	if value == "" || len(value) > maxURLBytes || containsSensitiveMetadata(value) {
		return false
	}
	u, err := url.ParseRequestURI(value)
	if err != nil || u.Scheme != "https" || u.Host != strings.ToLower(u.Host) || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Hostname() == "" || u.String() != value {
		return false
	}
	return !strings.ContainsAny(u.Host, "\\@")
}

func validSyntheticSourceReference(value string) bool {
	if !validSafeToken(value, maxReferenceBytes) || !strings.HasPrefix(value, "internal/providerbridge/testdata/") || !strings.HasSuffix(value, ".json") || path.Clean(value) != value || strings.Contains(value, "//") {
		return false
	}
	return map[string]bool{
		"internal/providerbridge/testdata/codex.json":         true,
		"internal/providerbridge/testdata/claude.json":        true,
		"internal/providerbridge/testdata/qwen-general.json":  true,
		"internal/providerbridge/testdata/qwen-local-pd.json": true,
		"internal/providerbridge/testdata/kimi.json":          true,
		"internal/providerbridge/testdata/deepseek.json":      true,
	}[value]
}

func validSourceReference(value string, maturity CompatibilityMaturity) bool {
	if maturity == CompatibilitySynthetic {
		return validSyntheticSourceReference(value)
	}
	return maturity == CompatibilityPinned && validHTTPSURL(value)
}
