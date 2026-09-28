package core

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

type Classification string

const (
	L0 Classification = "L0"
	L1 Classification = "L1"
	L2 Classification = "L2"
	L3 Classification = "L3"
)

func (c Classification) Valid() bool {
	switch c {
	case L0, L1, L2, L3:
		return true
	}
	return false
}
func (c Classification) Rank() int {
	switch c {
	case L0:
		return 0
	case L1:
		return 1
	case L2:
		return 2
	case L3:
		return 3
	default:
		return 99
	}
}

type Provenance struct {
	AdapterID      string    `json:"adapter_id"`
	AccountID      string    `json:"account_id"`
	SourceEventID  string    `json:"source_event_id"`
	SchemaVersion  string    `json:"schema_version"`
	TraceID        string    `json:"trace_id"`
	Channel        string    `json:"channel"`
	ConversationID string    `json:"conversation_id"`
	Sender         string    `json:"sender"`
	Locator        string    `json:"locator,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
	Version        int       `json:"version"`
	Digest         string    `json:"digest,omitempty"`
	Timezone       string    `json:"timezone,omitempty"`
	IngestedAt     time.Time `json:"ingested_at"`
}
type InboundEvent struct {
	ID             string            `json:"id"`
	Text           string            `json:"text"`
	Provenance     Provenance        `json:"provenance"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	Classification Classification    `json:"classification"`
}
type Candidate struct {
	ID             string         `json:"id"`
	Kind           string         `json:"kind"`
	Summary        string         `json:"summary"`
	Source         Provenance     `json:"source"`
	Confidence     float64        `json:"confidence"`
	Status         string         `json:"status"`
	Classification Classification `json:"classification"`
}
type Health struct {
	Status     string `json:"status"`
	Mode       string `json:"mode"`
	QueueDepth int    `json:"queue_depth"`
	Gap        bool   `json:"gap"`
	Degraded   bool   `json:"degraded"`
	Reason     string `json:"reason,omitempty"`
}

func (e InboundEvent) Validate() error {
	if strings.TrimSpace(e.ID) == "" || strings.TrimSpace(e.Text) == "" {
		return errors.New("id and text are required")
	}
	p := e.Provenance
	if p.AdapterID == "" || p.AccountID == "" || p.SourceEventID == "" || p.SchemaVersion != "1.0" || p.TraceID == "" || p.Channel == "" || p.ConversationID == "" || p.Sender == "" || p.Timestamp.IsZero() || p.IngestedAt.IsZero() || p.Version < 1 || p.Digest == "" || p.Timezone == "" || !e.Classification.Valid() {
		return errors.New("incomplete provenance")
	}
	return nil
}

type Queue interface {
	Enqueue(context.Context, InboundEvent) (bool, error)
	Dequeue(context.Context) (InboundEvent, bool, error)
	Depth() int
	Purge(context.Context) error
}
type MemoryQueue struct {
	mu     sync.Mutex
	events map[string]InboundEvent
	order  []string
}

func NewMemoryQueue() *MemoryQueue { return &MemoryQueue{events: make(map[string]InboundEvent)} }
func (q *MemoryQueue) Enqueue(ctx context.Context, e InboundEvent) (bool, error) {
	if err := e.Validate(); err != nil {
		return false, err
	}
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	key := e.Provenance.AdapterID + "\x00" + e.Provenance.AccountID + "\x00" + e.Provenance.SourceEventID
	old, ok := q.events[key]
	if ok && old.Provenance.Version >= e.Provenance.Version {
		return false, nil
	}
	if !ok {
		q.order = append(q.order, key)
	}
	q.events[key] = e
	return true, nil
}
func (q *MemoryQueue) Dequeue(ctx context.Context) (InboundEvent, bool, error) {
	select {
	case <-ctx.Done():
		return InboundEvent{}, false, ctx.Err()
	default:
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.order) == 0 {
		return InboundEvent{}, false, nil
	}
	k := q.order[0]
	q.order = q.order[1:]
	e := q.events[k]
	delete(q.events, k)
	return e, true, nil
}
func (q *MemoryQueue) Depth() int { q.mu.Lock(); defer q.mu.Unlock(); return len(q.order) }
func (q *MemoryQueue) Purge(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.events = make(map[string]InboundEvent)
	q.order = nil
	return nil
}

type DLP struct{}

var dlpPatterns = []*regexp.Regexp{regexp.MustCompile(`(?i)(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})`), regexp.MustCompile(`\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b`), regexp.MustCompile(`\+?[0-9][0-9 ()-]{8,}[0-9]`), regexp.MustCompile(`(?i)\b(?:iban|passport|ssn|инн|паспорт|карта|сч[её]т|зарплат|диагноз|медицин|больнич|hr|увольн|адвокат|суд|договор)\b`)}

func (DLP) Classify(text string) Classification {
	low := strings.ToLower(text)
	for _, term := range []string{"договор", "зарплат", "диагноз", "медицин", "больнич", "увольн", "адвокат", "паспорт", "инн", "счёт", "счет"} {
		if strings.Contains(low, term) {
			return L2
		}
	}
	for i, p := range dlpPatterns {
		if p.MatchString(text) {
			if i == 0 {
				return L3
			}
			return L2
		}
	}
	if strings.TrimSpace(text) == "" {
		return L2
	}
	return L2
}

type LocalModel interface {
	Classify(context.Context, string) (Classification, error)
}
type DisabledModel struct{}

func (DisabledModel) Classify(context.Context, string) (Classification, error) {
	return L1, errors.New("local model disabled")
}
func ClassifyWithModel(ctx context.Context, text string, d DLP, m LocalModel) (Classification, error) {
	det := d.Classify(text)
	if m == nil {
		return det, nil
	}
	proposed, err := m.Classify(ctx, text)
	if err != nil || !proposed.Valid() {
		return det, err
	}
	if proposed.Rank() > det.Rank() {
		return proposed, nil
	}
	return det, nil
}

type Pseudonymizer interface {
	Token(scope, value string) (string, error)
	SessionRef(owner, purpose, adapter, account, channel, conversation string) (string, error)
	RehydrateResponse(context.Context, string, string) (string, error)
	PurgeScope(context.Context, string) error
	Purge(context.Context) error
}

type EphemeralPseudonymizer struct {
	mu      sync.Mutex
	scopes  map[string]map[string]string
	reverse map[string]map[string]string
	key     []byte
}

func NewPseudonymizer() *EphemeralPseudonymizer {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return NewPseudonymizerWithKey(key)
}
func NewPseudonymizerWithKey(key []byte) *EphemeralPseudonymizer {
	if len(key) < 16 {
		panic("pseudonym key must be at least 128 bits")
	}
	return &EphemeralPseudonymizer{scopes: map[string]map[string]string{}, reverse: map[string]map[string]string{}, key: append([]byte(nil), key...)}
}
func (p *EphemeralPseudonymizer) Pseudonym(scope, value string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.scopes[scope] == nil {
		p.scopes[scope] = map[string]string{}
		p.reverse[scope] = map[string]string{}
	}
	if x := p.scopes[scope][value]; x != "" {
		return x
	}
	m := hmac.New(sha256.New, p.key)
	_, _ = m.Write([]byte(scope + "\x00" + value))
	h := m.Sum(nil)
	x := "P-" + strings.ToUpper(hex.EncodeToString(h)[:32])
	p.scopes[scope][value] = x
	p.reverse[scope][x] = value
	return x
}
func (p *EphemeralPseudonymizer) Token(scope, value string) (string, error) {
	return p.Pseudonym(scope, value), nil
}
func (p *EphemeralPseudonymizer) SessionRef(owner, purpose, adapter, account, channel, conversation string) (string, error) {
	return "psn_" + p.Pseudonym(strings.Join([]string{owner, purpose, adapter, account, channel}, "/"), conversation)[2:], nil
}
func SessionRef(p *EphemeralPseudonymizer, owner, purpose, adapter, account, channel, conversation string) string {
	x, _ := p.SessionRef(owner, purpose, adapter, account, channel, conversation)
	return x
}
func (p *EphemeralPseudonymizer) RehydrateResponse(ctx context.Context, scope, text string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	re := regexp.MustCompile(`\bP-[A-F0-9]{32}\b`)
	unknown := error(nil)
	out := re.ReplaceAllStringFunc(text, func(tok string) string {
		v, ok := p.Rehydrate(scope, tok)
		if !ok {
			unknown = fmt.Errorf("unknown pseudonym token")
			return tok
		}
		return v
	})
	if unknown != nil {
		return "", unknown
	}
	return out, nil
}
func (p *EphemeralPseudonymizer) Rehydrate(scope, token string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.reverse[scope][token]
	return v, ok
}
func (p *EphemeralPseudonymizer) PurgeScope(ctx context.Context, scope string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.scopes, scope)
	delete(p.reverse, scope)
	return nil
}
func (p *EphemeralPseudonymizer) Purge(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.scopes = map[string]map[string]string{}
	p.reverse = map[string]map[string]string{}
	return nil
}

type SafeEnvelope struct {
	SchemaVersion string              `json:"schema_version"`
	Purpose       string              `json:"purpose"`
	SessionRef    string              `json:"session_ref"`
	Messages      []EnvelopeMessage   `json:"messages"`
	Constraints   EnvelopeConstraints `json:"constraints"`
	Attestation   EgressAttestation   `json:"egress_attestation"`
}
type EnvelopeMessage struct {
	Speaker      string `json:"speaker"`
	Text         string `json:"text"`
	RelativeTime string `json:"relative_time,omitempty"`
}
type EnvelopeConstraints struct {
	Language         string   `json:"language"`
	Tone             string   `json:"tone"`
	ForbiddenActions []string `json:"forbidden_actions"`
}
type EgressAttestation struct {
	PolicyVersion string         `json:"policy_version"`
	MaxClass      Classification `json:"max_class"`
	Decision      string         `json:"decision"`
	Digest        string         `json:"digest"`
}
type SanitizedMessage struct{ Speaker, Text, RelativeTime string }
type SafeEnvelopeContext struct{ Owner, Purpose string }

func ScanSanitized(text string) Classification {
	latin, cyr := false, false
	for _, r := range text {
		if unicode.Is(unicode.Cf, r) {
			return L2
		}
		if unicode.In(r, unicode.Latin) {
			latin = true
		}
		if unicode.Is(unicode.Cyrillic, r) {
			cyr = true
		}
	}
	if strings.ContainsAny(text, "０１２３４５６７８９＠．－＿") {
		return L2
	}
	if latin && cyr {
		return L2
	}
	for i, p := range dlpPatterns {
		if p.MatchString(text) {
			if i == 0 {
				return L3
			}
			return L2
		}
	}
	low := strings.ToLower(text)
	if (latin || cyr) && strings.IndexFunc(text, func(r rune) bool { return unicode.IsDigit(r) || strings.ContainsRune("@._-", r) }) >= 0 {
		return L2
	}
	for _, term := range []string{"договор", "зарплат", "диагноз", "медицин", "больнич", "увольн", "адвокат", "паспорт", "инн", "счёт", "счет"} {
		if strings.Contains(low, term) {
			return L2
		}
	}
	if strings.TrimSpace(text) == "" {
		return L2
	}
	return L1
}

func BuildSafeEnvelopeFromSanitizedWithContext(e InboundEvent, p Pseudonymizer, m SanitizedMessage, c SafeEnvelopeContext) (SafeEnvelope, error) {
	if strings.TrimSpace(c.Owner) == "" || strings.TrimSpace(c.Purpose) == "" {
		return SafeEnvelope{}, errors.New("envelope context required")
	}
	if c.Purpose != "summarize" && c.Purpose != "draft_reply" && c.Purpose != "extract_candidates" {
		return SafeEnvelope{}, errors.New("unsupported purpose")
	}
	if utf8.RuneCountInString(m.Text) > 4000 || utf8.RuneCountInString(m.RelativeTime) > 80 {
		return SafeEnvelope{}, errors.New("message too long")
	}
	if err := e.Validate(); err != nil {
		return SafeEnvelope{}, err
	}
	max := ScanSanitized(m.Text)
	if max > L1 {
		return SafeEnvelope{}, errors.New("sanitized post-scan denied")
	}
	scope := strings.Join([]string{c.Owner, c.Purpose, e.Provenance.AdapterID, e.Provenance.AccountID, e.Provenance.Channel, e.Provenance.ConversationID}, "/")
	pseudo, err := p.Token(scope, m.Speaker)
	if err != nil {
		return SafeEnvelope{}, fmt.Errorf("pseudonymize speaker: %w", err)
	}
	session, err := p.SessionRef(c.Owner, c.Purpose, e.Provenance.AdapterID, e.Provenance.AccountID, e.Provenance.Channel, e.Provenance.ConversationID)
	if err != nil {
		return SafeEnvelope{}, fmt.Errorf("pseudonymize session: %w", err)
	}
	sum := sha256.Sum256([]byte(m.Text))
	return SafeEnvelope{"1.0", c.Purpose, session, []EnvelopeMessage{{pseudo, m.Text, m.RelativeTime}}, EnvelopeConstraints{"ru", "concise", []string{"send", "mutate"}}, EgressAttestation{"egress-1", max, "allow", "sha256:" + hex.EncodeToString(sum[:])}}, nil
}

func BuildSafeEnvelope(e InboundEvent, p Pseudonymizer) (SafeEnvelope, error) {
	if err := e.Validate(); err != nil {
		return SafeEnvelope{}, err
	}
	return SafeEnvelope{}, fmt.Errorf("raw event requires explicit sanitization")
}

type Audit interface {
	Record(context.Context, string, map[string]string) error
}
type RedactedAudit struct {
	mu      sync.Mutex
	Entries []map[string]string
}

func (a *RedactedAudit) Record(ctx context.Context, event string, fields map[string]string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if v := fields["id"]; v != "" && !regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`).MatchString(v) {
		return errors.New("audit id must be opaque")
	}
	if v := fields["reason"]; v != "" && v != "uncertain" && v != "sensitive" && v != "denied" && v != "degraded" {
		return errors.New("invalid audit reason")
	}
	x := map[string]string{"event": event}
	for _, k := range []string{"id", "classification", "reason", "mode"} {
		if v := fields[k]; v != "" {
			x[k] = v
		}
	}
	a.Entries = append(a.Entries, x)
	return nil
}

type Notification struct {
	EventID      string    `json:"event_id"`
	Channel      string    `json:"channel"`
	Conversation string    `json:"conversation"`
	Sender       string    `json:"sender"`
	Summary      string    `json:"summary"`
	Priority     string    `json:"priority"`
	Mode         string    `json:"mode"`
	Gap          bool      `json:"gap"`
	Degraded     bool      `json:"degraded"`
	Uncertain    bool      `json:"uncertain"`
	OccurredAt   time.Time `json:"occurred_at"`
}

func Watch(e InboundEvent, mode string, gap, degraded bool) (Notification, error) {
	if err := e.Validate(); err != nil {
		return Notification{}, err
	}
	c := DLP{}.Classify(e.Text)
	pr := "normal"
	if strings.Contains(strings.ToLower(e.Text), "срочно") || strings.Contains(strings.ToLower(e.Text), "urgent") {
		pr = "high"
	}
	sender := e.Provenance.Sender
	summary := truncate(e.Text, 160)
	uncertain := c == L2 || c == L3
	if uncertain {
		sender = "[masked]"
		e.Provenance.ConversationID = "[masked]"
		summary = "[sensitive content masked]"
	}
	return Notification{EventID: e.ID, Channel: e.Provenance.Channel, Conversation: e.Provenance.ConversationID, Sender: sender, Summary: summary, Priority: pr, Mode: mode, Gap: gap, Degraded: degraded, Uncertain: uncertain, OccurredAt: e.Provenance.Timestamp}, nil
}
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
func Purge(ctx context.Context, q Queue, p Pseudonymizer, scope string) error {
	if err := q.Purge(ctx); err != nil {
		return err
	}
	return p.PurgeScope(ctx, scope)
}
func SortCandidates(c []Candidate) {
	sort.SliceStable(c, func(i, j int) bool { return c[i].Confidence > c[j].Confidence })
}
