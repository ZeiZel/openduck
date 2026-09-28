package macosattest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

var receiptKeys = strings.Fields("action association_digest capabilities capability_digest controller_binding_id endpoint_expires_at endpoint_generation endpoint_id expires_at issued_at key_id mesh_session_id native_host_artifact_digest native_host_catalog_generation native_host_image_identity native_host_team_id native_lifecycle_expires_at native_lifecycle_projection_digest native_manifest_digest native_provider_topology_digest native_release_digest native_release_id native_shim_artifact_digest native_socket_generation native_socket_identity_digest nonce package_digest package_id previous_receipt_digest profile_id profile_revision provider receipt_digest receipt_id root_run_id run_id schema_version signature ui_channel_id ui_session_id")
var childCapabilities = []string{"spawn", "spawnBatch", "send", "steer", "wait", "collect", "cancel", "list", "status", "result", "listProfiles"}

func VerifyNativeReceiptChain(raw []byte, public ed25519.PublicKey, projection LifecycleProjection, now time.Time) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > 256<<10 || len(public) != ed25519.PublicKeySize {
		return nil, ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var chain []map[string]any
	if d.Decode(&chain) != nil || len(chain) == 0 || len(chain) > 64 {
		return nil, ErrUnavailable
	}
	previous := ""
	seen := map[string]string{}
	var current map[string]any
	provider, profile, revision := "", "", ""
	binding := ""
	revoked := false
	for _, r := range chain {
		if len(r) != len(receiptKeys) {
			return nil, ErrUnavailable
		}
		for _, k := range receiptKeys {
			if _, ok := r[k]; !ok {
				return nil, ErrUnavailable
			}
		}
		if stringValue(r, "schema_version") != "openduck-native-package-lifecycle-receipt.v1" {
			return nil, ErrUnavailable
		}
		if stringValue(r, "package_id") != "openduck-mesh" || stringValue(r, "key_id") != projection.SignerKeyID {
			return nil, ErrUnavailable
		}
		caps, ok := r["capabilities"].([]any)
		if !ok || len(caps) != len(childCapabilities) {
			return nil, ErrUnavailable
		}
		for i, v := range caps {
			if v != childCapabilities[i] {
				return nil, ErrUnavailable
			}
		}
		capRaw, _ := canonicalJSON(caps)
		capSum := sha256.Sum256(capRaw)
		if stringValue(r, "capability_digest") != hex.EncodeToString(capSum[:]) {
			return nil, ErrUnavailable
		}
		action := stringValue(r, "action")
		if revoked || (action != "enable" && action != "disable" && action != "revoke") {
			return nil, ErrUnavailable
		}
		if action == "revoke" {
			revoked = true
		}
		if provider == "" {
			provider = stringValue(r, "provider")
			profile = stringValue(r, "profile_id")
			revision = stringValue(r, "profile_revision")
		} else if provider != stringValue(r, "provider") || profile != stringValue(r, "profile_id") || revision != stringValue(r, "profile_revision") {
			return nil, ErrUnavailable
		}
		bindingKeys := []string{"package_id", "package_digest", "controller_binding_id", "ui_session_id", "ui_channel_id", "root_run_id", "run_id", "mesh_session_id", "endpoint_id", "association_digest", "capability_digest", "native_lifecycle_projection_digest"}
		bm := map[string]any{}
		for _, k := range bindingKeys {
			bm[k] = r[k]
		}
		bb, _ := canonicalJSON(bm)
		if binding == "" {
			binding = string(bb)
		} else if binding != string(bb) {
			return nil, ErrUnavailable
		}
		id, digest := stringValue(r, "receipt_id"), stringValue(r, "receipt_digest")
		if id == "" || len(digest) != 64 || stringValue(r, "previous_receipt_digest") != previous {
			return nil, ErrUnavailable
		}
		if prior := seen[id]; prior != "" && prior != digest {
			return nil, ErrUnavailable
		}
		seen[id] = digest
		unsigned := map[string]any{}
		for k, v := range r {
			if k != "receipt_digest" && k != "signature" {
				unsigned[k] = v
			}
		}
		canonical, err := canonicalJSON(unsigned)
		if err != nil {
			return nil, ErrUnavailable
		}
		sum := sha256.Sum256(canonical)
		if digest != hex.EncodeToString(sum[:]) {
			return nil, ErrUnavailable
		}
		sig, err := base64.RawURLEncoding.DecodeString(stringValue(r, "signature"))
		if err != nil || len(sig) != 64 || !ed25519.Verify(public, canonical, sig) {
			return nil, ErrUnavailable
		}
		if !receiptProjectionMatch(r, projection) {
			return nil, ErrUnavailable
		}
		expires, err := time.Parse(time.RFC3339Nano, stringValue(r, "expires_at"))
		issued, issuedErr := time.Parse(time.RFC3339Nano, stringValue(r, "issued_at"))
		endpointExpires, endpointErr := time.Parse(time.RFC3339Nano, stringValue(r, "endpoint_expires_at"))
		lifecycleExpires, lifecycleErr := time.Parse(time.RFC3339Nano, stringValue(r, "native_lifecycle_expires_at"))
		if err != nil || issuedErr != nil || endpointErr != nil || lifecycleErr != nil || !issued.Before(expires) || !issued.Before(endpointExpires) || !issued.Before(lifecycleExpires) || !now.Before(expires) || !now.Before(endpointExpires) || !now.Before(lifecycleExpires) {
			return nil, ErrUnavailable
		}
		previous = digest
		current = r
	}
	return current, nil
}
func receiptProjectionMatch(r map[string]any, p LifecycleProjection) bool {
	trim := func(v string) string { return strings.TrimPrefix(v, "sha256:") }
	num := func(k string) uint64 {
		n, ok := r[k].(json.Number)
		if !ok {
			return 0
		}
		v, _ := n.Int64()
		return uint64(v)
	}
	return stringValue(r, "native_lifecycle_projection_digest") == trim(p.Digest) && stringValue(r, "native_release_id") == p.ReleaseID && stringValue(r, "native_release_digest") == trim(p.ReleaseDigest) && stringValue(r, "native_manifest_digest") == trim(p.ManifestDigest) && stringValue(r, "native_shim_artifact_digest") == trim(p.ShimArtifactDigest) && num("native_socket_generation") == p.SocketGeneration && stringValue(r, "native_socket_identity_digest") == trim(p.SocketIdentityDigest) && num("native_host_catalog_generation") == p.HostCatalogGeneration && stringValue(r, "native_provider_topology_digest") == trim(p.ProviderTopologyDigest) && stringValue(r, "native_host_artifact_digest") == trim(p.HostArtifactDigest) && stringValue(r, "native_host_team_id") == p.HostTeamID && stringValue(r, "native_host_image_identity") == trim(p.HostImageIdentity) && stringValue(r, "native_lifecycle_expires_at") == p.ExpiresAt.Format(time.RFC3339Nano)
}
func stringValue(v map[string]any, k string) string { s, _ := v[k].(string); return s }
func canonicalJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func writeCanonical(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			raw, _ := json.Marshal(k)
			b.Write(raw)
			b.WriteByte(':')
			if err := writeCanonical(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	default:
		raw, err := json.Marshal(x)
		if err != nil {
			return err
		}
		b.Write(raw)
	}
	return nil
}
