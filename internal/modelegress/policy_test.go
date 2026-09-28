package modelegress

import (
	"strings"
	"testing"
)

func testPolicy(t *testing.T) Policy {
	t.Helper()
	p, err := NewPolicy([]string{"api.openai.com", "chat.openai.com"}, 501, 502, "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), 7)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPolicyCanonicalAndCapability(t *testing.T) {
	p := testPolicy(t)
	b, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":"model-egress.v1","allowed_hosts":["api.openai.com","chat.openai.com"],"port":443,"proxy_uid":501,"proxy_gid":502,"release_digest":"sha256:` + strings.Repeat("a", 64) + `","socket_digest":"sha256:` + strings.Repeat("b", 64) + `","epoch":7}`
	if string(b) != want {
		t.Fatalf("canonical=%s", b)
	}
	cap, err := issueCapability(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCapability(p, cap); err != nil {
		t.Fatal(err)
	}
	if err := verifyCapability(p, fakeCapability{}); err == nil {
		t.Fatal("forged capability accepted")
	}
}

type fakeCapability struct{}

func (fakeCapability) productionCapability() {}

func TestPolicyRejectsWildcardsAndIP(t *testing.T) {
	for _, host := range []string{"*.openai.com", "127.0.0.1", "api.openai.com.", "API.OPENAI.COM", "openai_com"} {
		if _, err := NewPolicy([]string{host}, 1, 2, "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), 1); err == nil {
			t.Errorf("accepted %q", host)
		}
	}
}
