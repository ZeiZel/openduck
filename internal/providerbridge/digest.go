package providerbridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

func digest(value any) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// DigestBytes returns the canonical lowercase SHA-256 content digest for a
// bounded sanitized descriptor supplied to the offline compatibility builder.
func DigestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || value[:7] != "sha256:" {
		return false
	}
	encoded := value[7:]
	_, err := hex.DecodeString(encoded)
	return err == nil && encoded == strings.ToLower(encoded)
}
