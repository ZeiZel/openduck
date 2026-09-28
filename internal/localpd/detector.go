package localpd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Class string

const (
	ClassL0 Class = "L0"
	ClassL1 Class = "L1"
	ClassL2 Class = "L2"
	ClassL3 Class = "L3"
)

type DetectionMode string

const (
	ModeNormal     DetectionMode = "normal"
	ModeQuarantine DetectionMode = "quarantine"
	ModePD         DetectionMode = "pd"
	ModeClosed     DetectionMode = "closed"
)

// SourceEvent is the only input carrying message bytes. Content is inspected
// synchronously and is never returned or persisted.
type SourceEvent struct {
	ConversationID    string
	Revision          uint64
	SourceSequence    uint64
	IngestOrdinal     uint64
	ScannedThrough    uint64
	Complete          bool
	Gap               bool
	PendingParts      bool
	Backfill          bool
	Revoked           bool
	Deleted           bool
	PolicyVersion     uint64
	PolicyDigest      string
	CoverageDigest    string
	RevisionSetDigest string
	Content           []byte
}

type Detection struct {
	Class         Class
	Mode          DetectionMode
	Marker        bool
	RuleIDs       []string
	ContentDigest string
}

type Detector struct{}

func (Detector) Detect(event SourceEvent) (Detection, error) { return Detect(event) }

var (
	ErrInvalidSourceEvent = errors.New("invalid local-pd source event")
	ErrQuarantinedInput   = errors.New("local-pd source event requires quarantine")
	phonePattern          = regexp.MustCompile(`(?:^|[^0-9])(?:\+?[0-9][0-9 ()-]{7,}[0-9])(?:$|[^0-9])`)
	emailPattern          = regexp.MustCompile(`(?i)\b[[:alnum:]._%+-]+@[[:alnum:].-]+\.[A-Z]{2,}\b`)
	cardPattern           = regexp.MustCompile(`\b(?:[0-9][ -]?){13,19}\b`)
	secretPattern         = regexp.MustCompile(`(?i)\b(?:sk-[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|bearer\s+[A-Za-z0-9._~-]{16,})\b`)
	injectionPattern      = regexp.MustCompile(`(?i)\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior)\s+instructions\b`)
)

func digestContent(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Detect accepts only the frozen byte grammar: one optional leading UTF-8
// BOM, ASCII SP/HT, exact "Это ПД", then CRLF or EOF. Marker-like text after
// normalization is quarantined. Internal BOMs, bidi controls,
// default-ignorables, combining marks, non-ASCII spacing and homoglyphs are
// never silently ignored.
func Detect(event SourceEvent) (Detection, error) {
	if event.ConversationID == "" || event.Revision == 0 || event.SourceSequence == 0 || event.IngestOrdinal == 0 || event.ScannedThrough == 0 || !event.Complete || event.Gap || event.PendingParts || event.Backfill || event.Revoked || event.Deleted || !utf8.Valid(event.Content) {
		return Detection{}, ErrInvalidSourceEvent
	}
	d := Detection{Class: ClassL0, Mode: ModeNormal, RuleIDs: []string{}, ContentDigest: digestContent(event.Content)}
	line := event.Content
	hadLeadingBOM := false
	if len(line) >= 3 && string(line[:3]) == "\xef\xbb\xbf" {
		hadLeadingBOM = true
		line = line[3:]
	}
	first, exactTerminator := firstLogicalLine(line)
	trimmed := strings.TrimLeft(first, " \t")
	if trimmed == "Это ПД" && exactTerminator {
		d.Marker, d.Class, d.Mode = true, ClassL3, ModePD
		d.RuleIDs = []string{"explicit-pd-marker"}
		return d, nil
	}
	if hadLeadingBOM || markerLike(first) || containsUnsafeFormatRune(string(event.Content)) {
		d.Class, d.Mode, d.RuleIDs = ClassL3, ModeQuarantine, []string{"marker-confusable-or-hidden-character"}
		return d, nil
	}
	if emailPattern.Match(event.Content) || phonePattern.Match(event.Content) || cardPattern.Match(event.Content) {
		d.Class, d.Mode, d.RuleIDs = ClassL2, ModeQuarantine, []string{"structured-personal-data"}
		return d, nil
	}
	if secretPattern.Match(event.Content) {
		d.Class, d.Mode, d.RuleIDs = ClassL3, ModeQuarantine, []string{"credential-like-secret"}
		return d, nil
	}
	if injectionPattern.Match(event.Content) {
		d.Class, d.Mode, d.RuleIDs = ClassL1, ModeQuarantine, []string{"prompt-injection-like-content"}
		return d, nil
	}
	return d, nil
}

func firstLogicalLine(b []byte) (string, bool) {
	i := strings.IndexByte(string(b), '\n')
	if i < 0 {
		return string(b), true
	}
	if i == 0 || b[i-1] != '\r' {
		return string(b[:i]), false
	}
	return string(b[:i-1]), true
}

func containsUnsafeFormatRune(s string) bool {
	for i, r := range s {
		if r == '\ufeff' && i == 0 {
			continue
		}
		if isDefaultIgnorable(r) || unicode.Is(unicode.Bidi_Control, r) || unicode.Is(unicode.Mn, r) || (unicode.IsSpace(r) && r != ' ' && r != '\t' && r != '\r' && r != '\n') {
			return true
		}
	}
	return false
}

func isDefaultIgnorable(r rune) bool {
	return r == 0x00ad || r == 0x034f || r == 0x061c ||
		(r >= 0x115f && r <= 0x1160) || (r >= 0x17b4 && r <= 0x17b5) ||
		(r >= 0x180b && r <= 0x180f) || (r >= 0x200b && r <= 0x200f) ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2060 && r <= 0x206f) ||
		r == 0x3164 || (r >= 0xfe00 && r <= 0xfe0f) || r == 0xfeff || r == 0xffa0 ||
		(r >= 0x1bca0 && r <= 0x1bca3) || (r >= 0x1d173 && r <= 0x1d17a) ||
		(r >= 0xe0000 && r <= 0xe0fff)
}

func markerLike(s string) bool {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsSpace(r) || isDefaultIgnorable(r) || unicode.Is(unicode.Bidi_Control, r) || unicode.Is(unicode.Mn, r) {
			continue
		}
		if r >= 0xff01 && r <= 0xff5e {
			r -= 0xfee0
		}
		switch r {
		case 'э', 'е', 'ё', 'e', '3', 'ε':
			b.WriteRune('e')
		case 'т', 't', 'τ':
			b.WriteRune('t')
		case 'о', 'o', '0', 'ο':
			b.WriteRune('o')
		case 'п', 'n', 'p', 'π':
			b.WriteRune('p')
		case 'д', 'а', 'a', 'd', 'α', 'δ', '∆':
			b.WriteRune('d')
		default:
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				b.WriteRune(r)
			}
		}
	}
	x := b.String()
	return strings.Contains(x, "etopd") || levenshteinAtMost(x, "etopd", 2)
}

func levenshteinAtMost(a, b string, limit int) bool {
	ar, br := []rune(a), []rune(b)
	if len(ar)-len(br) > limit || len(br)-len(ar) > limit {
		return false
	}
	prev := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i, x := range ar {
		cur := make([]int, len(br)+1)
		cur[0] = i + 1
		rowMin := cur[0]
		for j, y := range br {
			cost := 0
			if x != y {
				cost = 1
			}
			cur[j+1] = min3(cur[j]+1, prev[j+1]+1, prev[j]+cost)
			if cur[j+1] < rowMin {
				rowMin = cur[j+1]
			}
		}
		if rowMin > limit {
			return false
		}
		prev = cur
	}
	return prev[len(br)] <= limit
}

func min3(a, b, c int) int {
	if a < b {
		b = a
	}
	if c < b {
		return c
	}
	return b
}
