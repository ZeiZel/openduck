// Package readiness validates bounded, non-secret operational evidence.
package readiness

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"openduck/internal/releasecatalog"
)

const (
	EvidenceSchema   = "openduck.provider-operational-evidence.v1"
	EvidenceLeaf     = "state/provider-operational-evidence.json"
	MaxEvidenceBytes = 256 << 10
	MaxEvidenceAge   = 15 * time.Minute
)

const (
	ReasonTopologyAbsent        = "provider_topology_absent"
	ReasonTopologyInvalid       = "provider_topology_invalid"
	ReasonEvidenceAbsent        = "provider_evidence_absent"
	ReasonEvidenceInvalid       = "provider_evidence_invalid"
	ReasonEvidenceStale         = "provider_evidence_stale"
	ReasonCoreActivation        = "core_activation_unverified"
	ReasonDaemonIdentity        = "provider_daemon_identity_unverified"
	ReasonChannelHealth         = "provider_channel_health_unverified"
	ReasonAccountCanary         = "provider_account_canary_unverified"
	ReasonRevisionCompatibility = "provider_revision_compatibility_unverified"
	ReasonSessionRecovery       = "provider_session_recovery_unverified"
)

var ErrInvalid = errors.New("provider readiness evidence invalid")

type ExpectedProvider struct {
	Provider, ProfileID, ProfileRevision         string
	TopologyDigest, InactiveDaemonPath, JobLabel string
	ServiceUser, ServiceGroup, ChannelGroup      string
}

type Activation struct {
	ReleaseID, ActiveRelease, ActivatedRelease string
	Complete                                   bool
}

// ProviderEvidence contains references and digests only. It intentionally
// cannot carry credentials, command output, prompts or provider responses.
type ProviderEvidence struct {
	Provider                 string    `json:"provider"`
	ProfileID                string    `json:"profile_id"`
	ProfileRevision          string    `json:"profile_revision"`
	TopologyDigest           string    `json:"topology_digest"`
	JobLabel                 string    `json:"job_label"`
	PID                      int       `json:"pid"`
	StartIdentity            string    `json:"start_identity"`
	ExecutingImageIdentity   string    `json:"executing_image_identity"`
	ServiceUser              string    `json:"service_user"`
	ServiceGroup             string    `json:"service_group"`
	ChannelPeerGroup         string    `json:"channel_peer_group"`
	ChannelPeerAuthenticated bool      `json:"channel_peer_authenticated"`
	ChannelDescriptorDigest  string    `json:"channel_descriptor_digest"`
	ChannelProofDigest       string    `json:"channel_proof_digest"`
	ChannelAuthenticated     bool      `json:"channel_authenticated"`
	AccountRef               string    `json:"account_ref"`
	CanaryRef                string    `json:"canary_ref"`
	CanaryResultDigest       string    `json:"canary_result_digest"`
	CompatibilityDigest      string    `json:"compatibility_digest"`
	ProviderEvidenceDigest   string    `json:"provider_evidence_digest"`
	CompatibilityFreshUntil  time.Time `json:"compatibility_fresh_until"`
	RecoveryProofDigest      string    `json:"recovery_proof_digest"`
	ReceiptStoreRevision     string    `json:"receipt_store_revision"`
	RequestIDRetention       bool      `json:"request_id_retention"`
	BindingDigestRetention   bool      `json:"binding_digest_retention"`
	InflightReconciled       bool      `json:"inflight_reconciled"`
	ObservedAt               time.Time `json:"observed_at"`
	ExpiresAt                time.Time `json:"expires_at"`
}

type Evidence struct {
	SchemaVersion string             `json:"schema_version"`
	ReleaseID     string             `json:"release_id"`
	ObservedAt    time.Time          `json:"observed_at"`
	ExpiresAt     time.Time          `json:"expires_at"`
	Providers     []ProviderEvidence `json:"providers"`
}

type LiveProvider struct {
	Provider, JobLabel, StartIdentity, ExecutingImageIdentity string
	ServiceUser, ServiceGroup, ChannelPeerGroup               string
	PID                                                       int
	Running, ChannelPeerAuthenticated                         bool
}

type Report struct {
	Operational bool     `json:"operational"`
	ReasonCodes []string `json:"reason_codes"`
}

func DiscoverExpected(root string) ([]ExpectedProvider, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, ErrInvalid
	}
	out := make([]ExpectedProvider, 0, 5)
	for _, provider := range []string{"claude", "codex", "deepseek", "kimi", "qwen"} {
		entry, found := releasecatalog.EntryFor("providers/" + provider + "/topology.json")
		if !found {
			return nil, ErrInvalid
		}
		path := filepath.Join(root, releasecatalog.InactiveProviderRoot, provider, "topology.json")
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > releasecatalog.ProviderTopologyMaxBytes {
			return nil, ErrInvalid
		}
		raw, err := os.ReadFile(path)
		topology, decodeErr := releasecatalog.DecodeProviderTopology(raw)
		canonical, canonicalErr := releasecatalog.CanonicalProviderTopology(entry)
		if err != nil || decodeErr != nil || canonicalErr != nil || !bytes.Equal(raw, canonical) || topology.Provider != entry.Provider || topology.ProfileID != entry.ProfileID || topology.ProfileRevision != entry.ProfileRevision {
			return nil, ErrInvalid
		}
		out = append(out, ExpectedProvider{Provider: provider, ProfileID: topology.ProfileID, ProfileRevision: topology.ProfileRevision, TopologyDigest: topology.Digest, InactiveDaemonPath: filepath.Join(root, releasecatalog.InactiveProviderRoot, provider, topology.ExpectedDaemonLeaf), JobLabel: topology.ExpectedJobLabel, ServiceUser: topology.ExpectedServiceUser, ServiceGroup: topology.ExpectedServiceGroup, ChannelGroup: topology.ExpectedChannelGroup})
	}
	return out, nil
}

func LoadEvidence(root string) (Evidence, error) {
	path := filepath.Join(root, EvidenceLeaf)
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxEvidenceBytes {
		return Evidence{}, ErrInvalid
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > MaxEvidenceBytes || !json.Valid(raw) || duplicateKeys(raw) {
		return Evidence{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var evidence Evidence
	if decoder.Decode(&evidence) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Evidence{}, ErrInvalid
	}
	canonical, err := json.Marshal(evidence)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Evidence{}, ErrInvalid
	}
	return evidence, nil
}

func Evaluate(expected []ExpectedProvider, evidence Evidence, activation Activation, live []LiveProvider, now time.Time) Report {
	reasons := map[string]bool{}
	add := func(reason string) { reasons[reason] = true }
	if len(expected) == 0 {
		add(ReasonTopologyAbsent)
	}
	if now.IsZero() || !safeID(activation.ReleaseID) || !activation.Complete || activation.ActiveRelease != activation.ReleaseID || activation.ActivatedRelease != activation.ReleaseID {
		add(ReasonCoreActivation)
	}
	if evidence.SchemaVersion != EvidenceSchema || evidence.ReleaseID != activation.ReleaseID || evidence.ObservedAt.IsZero() || evidence.ExpiresAt.IsZero() || evidence.ExpiresAt.Sub(evidence.ObservedAt) <= 0 || evidence.ExpiresAt.Sub(evidence.ObservedAt) > MaxEvidenceAge || len(evidence.Providers) != len(expected) {
		add(ReasonEvidenceInvalid)
	}
	if now.Before(evidence.ObservedAt) || !now.Before(evidence.ExpiresAt) {
		add(ReasonEvidenceStale)
	}
	evidenceByProvider := map[string]ProviderEvidence{}
	last := ""
	for _, provider := range evidence.Providers {
		if provider.Provider <= last || evidenceByProvider[provider.Provider].Provider != "" {
			add(ReasonEvidenceInvalid)
		}
		evidenceByProvider[provider.Provider] = provider
		last = provider.Provider
	}
	liveByProvider := map[string]LiveProvider{}
	for _, provider := range live {
		if provider.Provider == "" || liveByProvider[provider.Provider].Provider != "" {
			add(ReasonDaemonIdentity)
		}
		liveByProvider[provider.Provider] = provider
	}
	for _, want := range expected {
		got, found := evidenceByProvider[want.Provider]
		observed, liveFound := liveByProvider[want.Provider]
		if !found || got.Provider != want.Provider || got.ProfileID != want.ProfileID || got.ProfileRevision != want.ProfileRevision || got.TopologyDigest != want.TopologyDigest || !freshWindow(got.ObservedAt, got.ExpiresAt, now) {
			add(ReasonEvidenceInvalid)
			continue
		}
		if !liveFound || !observed.Running || observed.PID <= 0 || observed.PID != got.PID || observed.JobLabel != want.JobLabel || got.JobLabel != want.JobLabel || !safeRef(got.StartIdentity) || observed.StartIdentity != got.StartIdentity || !digest(got.ExecutingImageIdentity) || observed.ExecutingImageIdentity != got.ExecutingImageIdentity || observed.ServiceUser != want.ServiceUser || got.ServiceUser != want.ServiceUser || observed.ServiceGroup != want.ServiceGroup || got.ServiceGroup != want.ServiceGroup {
			add(ReasonDaemonIdentity)
		}
		if !got.ChannelAuthenticated || !observed.ChannelPeerAuthenticated || !got.ChannelPeerAuthenticated || observed.ChannelPeerGroup != want.ChannelGroup || got.ChannelPeerGroup != want.ChannelGroup || !digest(got.ChannelDescriptorDigest) || !digest(got.ChannelProofDigest) {
			add(ReasonChannelHealth)
		}
		if !safeRef(got.AccountRef) || !safeRef(got.CanaryRef) || !digest(got.CanaryResultDigest) {
			add(ReasonAccountCanary)
		}
		if !digest(got.CompatibilityDigest) || !digest(got.ProviderEvidenceDigest) || !got.CompatibilityFreshUntil.After(now) {
			add(ReasonRevisionCompatibility)
		}
		if !digest(got.RecoveryProofDigest) || !safeRef(got.ReceiptStoreRevision) || !got.RequestIDRetention || !got.BindingDigestRetention || !got.InflightReconciled {
			add(ReasonSessionRecovery)
		}
	}
	values := make([]string, 0, len(reasons))
	for reason := range reasons {
		values = append(values, reason)
	}
	sort.Strings(values)
	return Report{Operational: len(values) == 0, ReasonCodes: values}
}

func freshWindow(observed, expires, now time.Time) bool {
	return !observed.IsZero() && !expires.IsZero() && !now.Before(observed) && now.Before(expires) && expires.Sub(observed) > 0 && expires.Sub(observed) <= MaxEvidenceAge
}

func safeID(value string) bool { return safeRef(value) }
func safeRef(value string) bool {
	if value == "" || len(value) > 160 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}
func digest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

func duplicateKeys(raw []byte) bool {
	var scan func(*json.Decoder) bool
	scan = func(decoder *json.Decoder) bool {
		token, err := decoder.Token()
		if err != nil {
			return true
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for decoder.More() {
					key, keyErr := decoder.Token()
					name, ok := key.(string)
					if keyErr != nil || !ok || seen[name] {
						return true
					}
					seen[name] = true
					if scan(decoder) {
						return true
					}
				}
				_, err = decoder.Token()
				return err != nil
			case '[':
				for decoder.More() {
					if scan(decoder) {
						return true
					}
				}
				_, err = decoder.Token()
				return err != nil
			}
		}
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if scan(decoder) {
		return true
	}
	_, err := decoder.Token()
	return err != io.EOF
}
