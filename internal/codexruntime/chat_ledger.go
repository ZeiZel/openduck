package codexruntime

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrRunCAS = errors.New("chat run compare-and-swap failed")

func recordDigest(r ChatRunRecord) string {
	// Recovery metadata is local bookkeeping and is deliberately excluded from
	// the externally anchored lifecycle digest. This lets a successful replay
	// clear the token without changing the state that was anchored.
	r.PendingToken, r.PendingState, r.PendingDigest = "", "", ""
	r.PendingExpected, r.PendingNext = 0, 0
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
func casRequestID(token string, expected, next uint64) string {
	h := sha256.Sum256([]byte(token + ":" + strconv.FormatUint(expected, 10) + ":" + strconv.FormatUint(next, 10)))
	return "cas_" + hex.EncodeToString(h[:16])
}

type ChatRunRecord struct {
	RunID           string    `json:"run_id"`
	IdempotencyKey  string    `json:"idempotency_key"`
	ChatID          string    `json:"chat_id"`
	State           string    `json:"state"`
	Version         uint64    `json:"version"`
	ResultDigest    string    `json:"result_digest,omitempty"`
	ErrorCode       string    `json:"error_code,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
	PendingToken    string    `json:"pending_token,omitempty"`
	PendingState    string    `json:"pending_state,omitempty"`
	PendingExpected uint64    `json:"pending_expected,omitempty"`
	PendingNext     uint64    `json:"pending_next,omitempty"`
	PendingDigest   string    `json:"pending_digest,omitempty"`
}

// PendingCAS is the caller-stable durable operation token. It is safe to
// retain and submit again after a lost reply or process restart.
type PendingCAS struct {
	Token    string `json:"token"`
	RunID    string `json:"run_id"`
	Expected uint64 `json:"expected"`
	Next     uint64 `json:"next"`
	Digest   string `json:"digest"`
}

func (p PendingCAS) Valid() bool {
	return p.Token != "" && p.RunID != "" && p.Next == p.Expected+1 && strings.HasPrefix(p.Digest, "sha256:")
}

type ChatRunLedger struct {
	path       string
	aead       cipher.AEAD
	checkpoint ChatLedgerCheckpoint
	mu         sync.Mutex
}
type ChatLedgerCheckpoint interface {
	CompareAndSwapDigest(string, string, uint64, uint64, string) error
}

func pendingFor(r ChatRunRecord) (PendingCAS, bool) {
	if r.PendingToken == "" {
		return PendingCAS{}, false
	}
	return PendingCAS{Token: r.IdempotencyKey, RunID: r.RunID, Expected: r.PendingExpected, Next: r.PendingNext, Digest: r.PendingDigest}, true
}

// reconcileLocked retries the exact durable CAS request. On an ambiguous
// transport failure the prospective state remains pending with its token; on
// a definitive mismatch it becomes terminally uncertain and loses the token.
func (l *ChatRunLedger) reconcileLocked(records []ChatRunRecord, index int) error {
	r := records[index]
	p, ok := pendingFor(r)
	if !ok || l.checkpoint == nil {
		return nil
	}
	err := l.checkpoint.CompareAndSwapDigest(casRequestID(p.Token, p.Expected, p.Next), p.RunID, p.Expected, p.Next, p.Digest)
	if err != nil {
		// Preserve the exact prospective state, error code, token and digest.
		// The checkpoint seam does not expose a definitive-vs-ambiguous error
		// distinction, so every replay failure remains recoverable and the
		// service presents the pending token as fail-closed uncertainty.
		records[index] = r
		if storeErr := l.store(records); storeErr != nil {
			return storeErr
		}
		return ErrRunCAS
	}
	// State and ErrorCode are the prospective canonical lifecycle outcome and
	// must remain byte-for-byte stable across replay.
	r.PendingToken, r.PendingState, r.PendingDigest = "", "", ""
	r.PendingExpected, r.PendingNext = 0, 0
	records[index] = r
	return l.store(records)
}

func NewEncryptedChatRunLedger(path string, key []byte) (*ChatRunLedger, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(key) != 32 {
		return nil, ErrUnsafeRuntime
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &ChatRunLedger{path: path, aead: aead}, nil
}
func NewEncryptedChatRunLedgerWithCheckpoint(path string, key []byte, checkpoint ChatLedgerCheckpoint) (*ChatRunLedger, error) {
	if checkpoint == nil {
		return nil, ErrUnsafeRuntime
	}
	l, err := NewEncryptedChatRunLedger(path, key)
	if err != nil {
		return nil, err
	}
	l.checkpoint = checkpoint
	return l, nil
}

// MemoryChatCheckpoint is test-only. Production composition must supply an
// independently attested checkpoint adapter.
type MemoryChatCheckpoint struct {
	mu       sync.Mutex
	versions map[string]uint64
	requests map[string]struct{}
}

func NewMemoryChatCheckpoint() *MemoryChatCheckpoint {
	return &MemoryChatCheckpoint{versions: map[string]uint64{}, requests: map[string]struct{}{}}
}
func (m *MemoryChatCheckpoint) CompareAndSwapDigest(requestID string, id string, expected, next uint64, digest string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.requests[requestID]; ok {
		return nil
	}
	if m.versions[id] != expected || next != expected+1 || !strings.HasPrefix(digest, "sha256:") {
		return ErrRunCAS
	}
	m.versions[id] = next
	m.requests[requestID] = struct{}{}
	return nil
}

func (l *ChatRunLedger) Begin(chatID, idempotencyKey string, now time.Time) (ChatRunRecord, error) {
	if l == nil || chatID == "" || idempotencyKey == "" {
		return ChatRunRecord{}, ErrRunCAS
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	records, err := l.load()
	if err != nil {
		return ChatRunRecord{}, err
	}
	for _, r := range records {
		if r.IdempotencyKey == idempotencyKey {
			for i := range records {
				if records[i].RunID == r.RunID && records[i].PendingToken != "" {
					if err := l.reconcileLocked(records, i); err != nil {
						return ChatRunRecord{}, err
					}
					r = records[i]
				}
			}
			return r, nil
		}
	}
	id, err := secureRunID()
	if err != nil {
		return ChatRunRecord{}, err
	}
	r := ChatRunRecord{RunID: id, IdempotencyKey: idempotencyKey, ChatID: chatID, State: "pending", Version: 1, UpdatedAt: now.UTC(), PendingToken: idempotencyKey, PendingState: "pending", PendingExpected: 0, PendingNext: 1}
	r.PendingDigest = recordDigest(r)
	records = append(records, r)
	if err := l.store(records); err != nil {
		return ChatRunRecord{}, err
	}
	if l.checkpoint != nil {
		if err := l.checkpoint.CompareAndSwapDigest(casRequestID(r.IdempotencyKey, 0, 1), r.RunID, 0, 1, r.PendingDigest); err != nil {
			return ChatRunRecord{}, ErrRunCAS
		}
		r.PendingToken, r.PendingState, r.PendingDigest = "", "", ""
		r.PendingExpected, r.PendingNext = 0, 0
		records[len(records)-1] = r
		if err := l.store(records); err != nil {
			return ChatRunRecord{}, err
		}
	}
	return r, nil
}

func (l *ChatRunLedger) BeginPending(chatID, token string, now time.Time) (ChatRunRecord, PendingCAS, error) {
	if token == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return ChatRunRecord{}, PendingCAS{}, err
		}
		token = "pending_" + hex.EncodeToString(b[:])
	}
	p := PendingCAS{Token: token, Expected: 0, Next: 1}
	l.mu.Lock()
	defer l.mu.Unlock()
	records, err := l.load()
	if err != nil {
		return ChatRunRecord{}, p, err
	}
	for _, old := range records {
		if old.IdempotencyKey == token {
			p.RunID, p.Digest = old.RunID, recordDigest(old)
			return old, p, nil
		}
	}
	runID, err := secureRunID()
	if err != nil {
		return ChatRunRecord{}, p, err
	}
	r := ChatRunRecord{RunID: runID, IdempotencyKey: token, ChatID: chatID, State: "pending", Version: 1, UpdatedAt: now.UTC()}
	p.RunID, p.Digest = r.RunID, recordDigest(r)
	records = append(records, r)
	if err := l.store(records); err != nil {
		return ChatRunRecord{}, p, err
	}
	if l.checkpoint != nil {
		if err := l.checkpoint.CompareAndSwapDigest(casRequestID(p.Token, 0, 1), p.RunID, 0, 1, p.Digest); err != nil {
			// Preserve the exact prospective record digest. Reconciliation can
			// replay the same request after a lost reply.
			return r, p, err
		}
	}
	return r, p, nil
}

// ReconcilePendingCAS resolves a previously submitted token without creating
// a second operation. The encrypted ledger remains the source of durable
// lifecycle state across restarts.
func (l *ChatRunLedger) ReconcilePendingCAS(p PendingCAS) (ChatRunRecord, error) {
	if l == nil || !p.Valid() {
		return ChatRunRecord{}, ErrRunCAS
	}
	r, err := l.Get(p.RunID)
	if err != nil || r.IdempotencyKey != p.Token || r.RunID != p.RunID || r.Version != p.Next || recordDigest(r) != p.Digest {
		return ChatRunRecord{}, ErrRunCAS
	}
	if l.checkpoint != nil {
		if err := l.checkpoint.CompareAndSwapDigest(casRequestID(p.Token, p.Expected, p.Next), p.RunID, p.Expected, p.Next, p.Digest); err != nil {
			return ChatRunRecord{}, err
		}
	}
	return r, nil
}

func (l *ChatRunLedger) Transition(runID string, expected uint64, next, resultDigest, errorCode string, now time.Time) (ChatRunRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	records, err := l.load()
	if err != nil {
		return ChatRunRecord{}, err
	}
	for i, r := range records {
		if r.RunID != runID {
			continue
		}
		if r.PendingToken != "" {
			if err := l.reconcileLocked(records, i); err != nil {
				return ChatRunRecord{}, err
			}
			r = records[i]
		}
		if r.Version != expected || !validRunTransition(r.State, next) {
			return ChatRunRecord{}, ErrRunCAS
		}
		r.State, r.Version, r.ResultDigest, r.ErrorCode, r.UpdatedAt = next, r.Version+1, resultDigest, errorCode, now.UTC()
		r.PendingToken, r.PendingState = r.IdempotencyKey, next
		r.PendingExpected, r.PendingNext = expected, expected+1
		r.PendingDigest = recordDigest(r)
		records[i] = r
		// Persist first. The external monotonic anchor observes only durable
		// states, never a proposed answer that failed to reach disk.
		if err := l.store(records); err != nil {
			return ChatRunRecord{}, err
		}
		if l.checkpoint != nil {
			if err := l.checkpoint.CompareAndSwapDigest(casRequestID(r.IdempotencyKey, expected, expected+1), runID, expected, expected+1, r.PendingDigest); err != nil {
				// The exact prospective state and request token remain durable so a
				// restarted service can replay the operation without caller memory.
				return ChatRunRecord{}, ErrRunCAS
			}
		}
		r.PendingToken, r.PendingState, r.PendingDigest = "", "", ""
		r.PendingExpected, r.PendingNext = 0, 0
		records[i] = r
		if err := l.store(records); err != nil {
			return ChatRunRecord{}, err
		}
		return records[i], nil
	}
	return ChatRunRecord{}, ErrRunCAS
}

func (l *ChatRunLedger) Get(runID string) (ChatRunRecord, error) {
	if l == nil || runID == "" {
		return ChatRunRecord{}, ErrRunCAS
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	records, err := l.load()
	if err != nil {
		return ChatRunRecord{}, err
	}
	for _, r := range records {
		if r.RunID == runID {
			return r, nil
		}
	}
	return ChatRunRecord{}, ErrRunCAS
}

func validRunTransition(from, to string) bool {
	switch from {
	case "pending":
		return to == "running" || to == "cancelled" || to == "failed"
	case "running":
		return to == "completed" || to == "failed" || to == "cancelled" || to == "uncertain"
	default:
		return false
	}
}
func secureRunID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "run_" + hex.EncodeToString(b), nil
}
func (l *ChatRunLedger) load() ([]ChatRunRecord, error) {
	raw, err := os.ReadFile(l.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) < l.aead.NonceSize() {
		return nil, ErrRunCAS
	}
	plain, err := l.aead.Open(nil, raw[:l.aead.NonceSize()], raw[l.aead.NonceSize():], nil)
	if err != nil {
		return nil, ErrRunCAS
	}
	var records []ChatRunRecord
	if json.Unmarshal(plain, &records) != nil {
		return nil, ErrRunCAS
	}
	return records, nil
}
func (l *ChatRunLedger) store(records []ChatRunRecord) error {
	plain, err := json.Marshal(records)
	if err != nil {
		return err
	}
	nonce := make([]byte, l.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	raw := append(nonce, l.aead.Seal(nil, nonce, plain, nil)...)
	dir := filepath.Dir(l.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".chat-ledger-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, l.path); err != nil {
		return err
	}
	// The external checkpoint may be advanced immediately after this method
	// returns. Persist the directory entry as well as the file contents so a
	// power loss cannot make the anchored pending token disappear.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	_ = d.Close()
	return err
}
func ChatAnswerDigest(answer string) string {
	h := sha256.Sum256([]byte(answer))
	return "sha256:" + hex.EncodeToString(h[:])
}
