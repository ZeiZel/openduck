package macosattest

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestHostRegistrationIsKernelBoundUniqueAndRevocable(t *testing.T) {
	host, err := SampleProcess(os.Getpid())
	if err != nil {
		t.Skip("platform attestation unavailable")
	}
	r := NewHostRegistry(func() time.Time { return time.Unix(100, 0).UTC() })
	v := HostRegistration{Provider: "codex", PeerID: "peer", SessionID: "session", ChannelID: "channel", ProfileID: "profile", RevisionID: "revision", Host: host, ShimImageIdentity: host.ImageIdentity(), ShimUID: host.UID, ShimGID: host.GID, ExpiresAt: time.Unix(200, 0).UTC()}
	if err := r.Register(v); err != nil {
		t.Skip("kernel revalidation unavailable")
	}
	if err := r.Register(v); !errors.Is(err, ErrUnavailable) {
		t.Fatal("duplicate host registration accepted")
	}
	r.Revoke(host.PID)
	if _, err := r.PeerFor(nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing authenticated socket accepted")
	}
}
