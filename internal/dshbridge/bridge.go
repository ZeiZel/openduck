// Package dshbridge contains the narrow, provider-free Controller contract
// consumed by an isolated Command Center UI.
package dshbridge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	UIChannelSessionV1 = "ui-channel-session.v1"
	ReadModelV1        = "command-center-read-model.v1"
	ComposerResultV1   = "composer-admission-result.v1"
	MaxComposerBytes   = 64 << 10
)

var (
	ErrUnavailable        = errors.New("controller unavailable")
	ErrUnauthorized       = errors.New("ui channel unauthorized")
	ErrReplay             = errors.New("ui channel replay")
	ErrExpired            = errors.New("ui channel expired")
	ErrInvalidRequest     = errors.New("invalid bridge request")
	ErrUnsupportedClass   = errors.New("unsupported privacy class")
	ErrPressure           = errors.New("ui channel capacity reached")
	ErrLocalPDUnavailable = errors.New("LOCAL_PD_UNAVAILABLE")
)

type PrivacyClass string

const (
	ClassL0 PrivacyClass = "L0"
	ClassL1 PrivacyClass = "L1"
	ClassL2 PrivacyClass = "L2"
	ClassL3 PrivacyClass = "L3"
)

type SafeProjection struct {
	Classification PrivacyClass `json:"classification"`
	Provenance     string       `json:"provenance"`
	Proof          string       `json:"proof"`
	Version        uint64       `json:"version"`
	ExpiresAt      time.Time    `json:"expires_at"`
}

// ProjectionVerifier is the trust boundary for read-model attestations. The
// payload is canonical JSON with the proof field blanked; implementations must
// verify the signature/binding, not merely its shape.
type ProjectionVerifier interface {
	Verify(route string, canonicalPayload []byte, projection SafeProjection, now time.Time) error
}

type Config struct {
	Origin              string
	Host                string
	SessionTTL          time.Duration
	RequestTTL          time.Duration
	Clock               func() time.Time
	Random              func([]byte) error
	MaxSessions         int
	MaxNoncesPerSession int
}

func (c Config) withDefaults() (Config, error) {
	if c.Origin == "" || c.Host == "" {
		return c, fmt.Errorf("origin and host are required: %w", ErrInvalidRequest)
	}
	u, err := url.Parse(c.Origin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !isLoopbackHost(u.Hostname()) {
		return c, fmt.Errorf("origin must be an exact loopback origin: %w", ErrInvalidRequest)
	}
	host, _, hostErr := net.SplitHostPort(c.Host)
	if hostErr != nil || !isLoopbackHost(host) {
		return c, fmt.Errorf("host must be an exact loopback authority: %w", ErrInvalidRequest)
	}
	if c.SessionTTL <= 0 {
		c.SessionTTL = 5 * time.Minute
	}
	if c.RequestTTL <= 0 {
		c.RequestTTL = 30 * time.Second
	}
	if c.MaxSessions <= 0 {
		c.MaxSessions = 256
	}
	if c.MaxNoncesPerSession <= 0 {
		c.MaxNoncesPerSession = 2048
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.Random == nil {
		c.Random = func(b []byte) error { _, err := rand.Read(b); return err }
	}
	return c, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type UIChannelSession struct {
	SchemaVersion string    `json:"schema_version"`
	SessionID     string    `json:"session_id"`
	ChannelID     string    `json:"channel_id"`
	Token         string    `json:"token"`
	ClientNonce   string    `json:"client_nonce"`
	Origin        string    `json:"origin"`
	Host          string    `json:"host"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Ephemeral     bool      `json:"ephemeral"`
	Persistent    bool      `json:"persistent"`
}

type sessionState struct {
	tokenHash    [32]byte
	sessionID    string
	channelID    string
	clientNonce  string
	expiresAt    time.Time
	usedRequests map[string]time.Time
}

// UIPrincipal is the only identity forwarded beyond the bearer verification
// boundary. It contains stable, bounded opaque identifiers and never the
// bearer token or its hash.
type UIPrincipal struct {
	SessionID string
	ChannelID string
}

type uiPrincipalContextKey struct{}

func WithUIPrincipal(ctx context.Context, principal UIPrincipal) context.Context {
	return context.WithValue(ctx, uiPrincipalContextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (UIPrincipal, bool) {
	p, ok := ctx.Value(uiPrincipalContextKey{}).(UIPrincipal)
	return p, ok && validUIPrincipal(p)
}

func validUIPrincipal(p UIPrincipal) bool {
	return len(p.SessionID) == base64.RawURLEncoding.EncodedLen(16) && len(p.ChannelID) == base64.RawURLEncoding.EncodedLen(16) && !strings.ContainsAny(p.SessionID+p.ChannelID, "\r\n")
}

type SessionStore struct {
	mu                 sync.Mutex
	config             Config
	sessions           map[[32]byte]sessionState
	issuedClientNonces map[string]time.Time
}

func NewSessionStore(config Config) (*SessionStore, error) {
	c, err := config.withDefaults()
	if err != nil {
		return nil, err
	}
	return &SessionStore{config: c, sessions: make(map[[32]byte]sessionState), issuedClientNonces: make(map[string]time.Time)}, nil
}

// Matches lets the transport prove that its configured authority is the same
// one that minted the in-memory session. It does not expose credentials.
func (s *SessionStore) Matches(origin, host string) bool {
	return s != nil && s.config.Origin == origin && s.config.Host == host
}

func (s *SessionStore) Issue(clientNonce string) (UIChannelSession, error) {
	if clientNonce == "" || len(clientNonce) > 128 || strings.ContainsAny(clientNonce, "\r\n") {
		return UIChannelSession{}, ErrInvalidRequest
	}
	raw := make([]byte, 32)
	if err := s.config.Random(raw); err != nil {
		return UIChannelSession{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	var sessionIDBytes [16]byte
	if err := s.config.Random(sessionIDBytes[:]); err != nil {
		return UIChannelSession{}, err
	}
	var channelIDBytes [16]byte
	if err := s.config.Random(channelIDBytes[:]); err != nil {
		return UIChannelSession{}, err
	}
	now := s.config.Clock().UTC()
	hash := sha256.Sum256([]byte(token))
	s.mu.Lock()
	s.sweepLocked(now)
	if len(s.sessions) >= s.config.MaxSessions {
		s.mu.Unlock()
		return UIChannelSession{}, ErrPressure
	}
	if _, exists := s.issuedClientNonces[clientNonce]; exists {
		s.mu.Unlock()
		return UIChannelSession{}, ErrReplay
	}
	s.issuedClientNonces[clientNonce] = now.Add(s.config.SessionTTL)
	sessionID := base64.RawURLEncoding.EncodeToString(sessionIDBytes[:])
	channelID := base64.RawURLEncoding.EncodeToString(channelIDBytes[:])
	s.sessions[hash] = sessionState{tokenHash: hash, sessionID: sessionID, channelID: channelID, clientNonce: clientNonce, expiresAt: now.Add(s.config.SessionTTL), usedRequests: make(map[string]time.Time)}
	s.mu.Unlock()
	return UIChannelSession{SchemaVersion: UIChannelSessionV1, SessionID: sessionID, ChannelID: channelID, Token: token, ClientNonce: clientNonce, Origin: s.config.Origin, Host: s.config.Host, IssuedAt: now, ExpiresAt: now.Add(s.config.SessionTTL), Ephemeral: true, Persistent: false}, nil
}

func (s *SessionStore) Authorize(token, clientNonce, requestNonce, origin, host string) error {
	_, err := s.AuthorizePrincipal(token, clientNonce, requestNonce, origin, host)
	return err
}

// AuthorizePrincipal consumes the request nonce and returns a non-bearer
// identity for trusted in-process consumers. Callers must never serialize it
// as a credential or use it as an endpoint capability.
func (s *SessionStore) AuthorizePrincipal(token, clientNonce, requestNonce, origin, host string) (UIPrincipal, error) {
	if token == "" || clientNonce == "" || requestNonce == "" || origin != s.config.Origin || host != s.config.Host {
		return UIPrincipal{}, ErrUnauthorized
	}
	hash := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.config.Clock().UTC())
	state, ok := s.sessions[hash]
	if !ok || subtle.ConstantTimeCompare(state.tokenHash[:], hash[:]) != 1 || state.clientNonce != clientNonce {
		return UIPrincipal{}, ErrUnauthorized
	}
	now := s.config.Clock().UTC()
	if !now.Before(state.expiresAt) {
		delete(s.sessions, hash)
		return UIPrincipal{}, ErrExpired
	}
	if _, used := state.usedRequests[requestNonce]; used {
		return UIPrincipal{}, ErrReplay
	}
	if len(requestNonce) > 128 || strings.ContainsAny(requestNonce, "\r\n") {
		return UIPrincipal{}, ErrInvalidRequest
	}
	if len(state.usedRequests) >= s.config.MaxNoncesPerSession {
		return UIPrincipal{}, ErrPressure
	}
	state.usedRequests[requestNonce] = now.Add(s.config.RequestTTL)
	s.sessions[hash] = state
	principal := UIPrincipal{SessionID: state.sessionID, ChannelID: state.channelID}
	if !validUIPrincipal(principal) {
		return UIPrincipal{}, ErrUnauthorized
	}
	return principal, nil
}

func (s *SessionStore) sweepLocked(now time.Time) {
	for hash, state := range s.sessions {
		if !now.Before(state.expiresAt) {
			delete(s.sessions, hash)
		}
	}
	for nonce, expires := range s.issuedClientNonces {
		if !now.Before(expires) {
			delete(s.issuedClientNonces, nonce)
		}
	}
}

type InboxItem struct {
	ID             string       `json:"id"`
	Summary        string       `json:"summary"`
	Source         string       `json:"source"`
	Classification PrivacyClass `json:"classification"`
	UpdatedAt      time.Time    `json:"updated_at"`
}
type InboxReadModel struct {
	SchemaVersion string         `json:"schema_version"`
	Projection    SafeProjection `json:"projection"`
	Items         []InboxItem    `json:"items"`
	GeneratedAt   time.Time      `json:"generated_at"`
}
type CalendarItem struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Timezone string    `json:"timezone"`
	Status   string    `json:"status"`
}
type CalendarReadModel struct {
	SchemaVersion string         `json:"schema_version"`
	Projection    SafeProjection `json:"projection"`
	Items         []CalendarItem `json:"items"`
	GeneratedAt   time.Time      `json:"generated_at"`
}
type WorkGraphReadModel struct {
	SchemaVersion   string          `json:"schema_version"`
	Projection      SafeProjection  `json:"projection"`
	GraphID         string          `json:"graph_id"`
	BaselineVersion string          `json:"baseline_version"`
	Nodes           []WorkGraphNode `json:"nodes"`
	Edges           []WorkGraphEdge `json:"edges"`
	GeneratedAt     time.Time       `json:"generated_at"`
}
type WorkGraphNode struct {
	ID           string     `json:"id"`
	Title        string     `json:"title"`
	Status       string     `json:"status"`
	PlannedStart *time.Time `json:"planned_start,omitempty"`
	PlannedEnd   *time.Time `json:"planned_end,omitempty"`
}
type WorkGraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}
type TaskItem struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Status  string `json:"status"`
	Source  string `json:"source"`
	Version uint64 `json:"version"`
}
type TasksReadModel struct {
	SchemaVersion string         `json:"schema_version"`
	Projection    SafeProjection `json:"projection"`
	Items         []TaskItem     `json:"items"`
	GeneratedAt   time.Time      `json:"generated_at"`
}
type TimeReadModel struct {
	SchemaVersion  string         `json:"schema_version"`
	Projection     SafeProjection `json:"projection"`
	ActiveTaskID   string         `json:"active_task_id,omitempty"`
	PlannedSeconds int64          `json:"planned_seconds"`
	SpentSeconds   int64          `json:"spent_seconds"`
	GeneratedAt    time.Time      `json:"generated_at"`
}
type ReviewItem struct {
	ID           string `json:"id"`
	TargetID     string `json:"target_id"`
	Status       string `json:"status"`
	FindingCount int    `json:"finding_count"`
}
type ReviewsReadModel struct {
	SchemaVersion string         `json:"schema_version"`
	Projection    SafeProjection `json:"projection"`
	Items         []ReviewItem   `json:"items"`
	GeneratedAt   time.Time      `json:"generated_at"`
}
type MemoryMetadata struct {
	ID              string `json:"id"`
	Scope           string `json:"scope"`
	Sensitivity     string `json:"sensitivity"`
	Status          string `json:"status"`
	ProvenanceCount int    `json:"provenance_count"`
}
type MemoryMetadataReadModel struct {
	SchemaVersion string           `json:"schema_version"`
	Projection    SafeProjection   `json:"projection"`
	Items         []MemoryMetadata `json:"items"`
	GeneratedAt   time.Time        `json:"generated_at"`
}
type HealthReadModel struct {
	SchemaVersion       string         `json:"schema_version"`
	Projection          SafeProjection `json:"projection"`
	Status              string         `json:"status"`
	ControllerAvailable bool           `json:"controller_available"`
	EffectsEnabled      bool           `json:"effects_enabled"`
	GeneratedAt         time.Time      `json:"generated_at"`
}

type ReadModels interface {
	ReadInbox(context.Context) (InboxReadModel, error)
	ReadCalendar(context.Context) (CalendarReadModel, error)
	ReadWorkGraph(context.Context) (WorkGraphReadModel, error)
	ReadTasks(context.Context) (TasksReadModel, error)
	ReadTime(context.Context) (TimeReadModel, error)
	ReadReviews(context.Context) (ReviewsReadModel, error)
	ReadMemoryMetadata(context.Context) (MemoryMetadataReadModel, error)
	ReadHealth(context.Context) (HealthReadModel, error)
}

// ReadResult is a discriminated union. Exactly one pointer is populated by
// Read; the transport never serializes an untyped or provider-owned value.
type ReadResult struct {
	Route          string
	Inbox          *InboxReadModel
	Calendar       *CalendarReadModel
	WorkGraph      *WorkGraphReadModel
	Tasks          *TasksReadModel
	Time           *TimeReadModel
	Reviews        *ReviewsReadModel
	MemoryMetadata *MemoryMetadataReadModel
	Health         *HealthReadModel
}

type Classifier interface {
	Classify([]byte) (PrivacyClass, error)
}
type AdmissionAuthority interface {
	AdmitCloud(context.Context, []byte) (CloudAdmission, error)
	DispatchLocalPD(context.Context, []byte) (LocalPDAdmission, error)
}
type CloudAdmission struct {
	ID     string
	Status string
}
type LocalPDAdmission struct {
	Handle string
	Status string
}
type ComposerResult struct {
	SchemaVersion string `json:"schema_version"`
	Route         string `json:"route"`
	AdmissionID   string `json:"admission_id,omitempty"`
	LocalPDHandle string `json:"local_pd_handle,omitempty"`
	Status        string `json:"status"`
}

var opaqueIDPattern = regexp.MustCompile(`^(?:adm|pd)_[A-Za-z0-9_-]{8,120}$`)

func validOpaqueID(id, prefix string) bool {
	lower := strings.ToLower(id)
	return opaqueIDPattern.MatchString(id) && strings.HasPrefix(id, prefix+"_") && !strings.Contains(lower, "sentinel") && !strings.Contains(lower, "qwen") && !strings.Contains(lower, "private")
}
func validCloudStatus(status string) bool {
	switch status {
	case "pending", "accepted", "consumed", "uncertain", "denied":
		return true
	}
	return false
}
func validLocalStatus(status string) bool {
	switch status {
	case "queued", "running", "completed", "expired", "denied":
		return true
	}
	return false
}

type Bridge struct {
	Sessions           *SessionStore
	Models             ReadModels
	Classifier         Classifier
	Authority          AdmissionAuthority
	ProjectionVerifier ProjectionVerifier
}

func (b *Bridge) Read(ctx context.Context, route string) (ReadResult, error) {
	if b.Models == nil {
		return ReadResult{}, ErrUnavailable
	}
	switch route {
	case "inbox":
		m, err := b.Models.ReadInbox(ctx)
		return ReadResult{Route: route, Inbox: &m}, err
	case "calendar":
		m, err := b.Models.ReadCalendar(ctx)
		return ReadResult{Route: route, Calendar: &m}, err
	case "workgraph":
		m, err := b.Models.ReadWorkGraph(ctx)
		return ReadResult{Route: route, WorkGraph: &m}, err
	case "tasks":
		m, err := b.Models.ReadTasks(ctx)
		return ReadResult{Route: route, Tasks: &m}, err
	case "time":
		m, err := b.Models.ReadTime(ctx)
		return ReadResult{Route: route, Time: &m}, err
	case "reviews":
		m, err := b.Models.ReadReviews(ctx)
		return ReadResult{Route: route, Reviews: &m}, err
	case "memory-metadata":
		m, err := b.Models.ReadMemoryMetadata(ctx)
		return ReadResult{Route: route, MemoryMetadata: &m}, err
	case "health":
		m, err := b.Models.ReadHealth(ctx)
		return ReadResult{Route: route, Health: &m}, err
	default:
		return ReadResult{}, ErrInvalidRequest
	}
}

func (b *Bridge) Compose(ctx context.Context, payload []byte) (ComposerResult, error) {
	if len(payload) == 0 || len(payload) > MaxComposerBytes || b.Classifier == nil || b.Authority == nil {
		return ComposerResult{}, ErrInvalidRequest
	}
	class, err := b.Classifier.Classify(append([]byte(nil), payload...))
	if err != nil {
		return ComposerResult{}, err
	}
	switch class {
	case ClassL0, ClassL1:
		admission, err := b.Authority.AdmitCloud(ctx, append([]byte(nil), payload...))
		if err != nil {
			return ComposerResult{}, err
		}
		if !validOpaqueID(admission.ID, "adm") || !validCloudStatus(admission.Status) {
			return ComposerResult{}, ErrInvalidRequest
		}
		return ComposerResult{SchemaVersion: ComposerResultV1, Route: "cloud", AdmissionID: admission.ID, Status: admission.Status}, nil
	case ClassL2, ClassL3:
		admission, err := b.Authority.DispatchLocalPD(ctx, append([]byte(nil), payload...))
		if err != nil {
			return ComposerResult{}, err
		}
		if !validOpaqueID(admission.Handle, "pd") || !validLocalStatus(admission.Status) {
			return ComposerResult{}, ErrInvalidRequest
		}
		return ComposerResult{SchemaVersion: ComposerResultV1, Route: "local_pd", LocalPDHandle: admission.Handle, Status: admission.Status}, nil
	default:
		return ComposerResult{}, ErrUnsupportedClass
	}
}
