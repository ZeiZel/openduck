package providerhostbridge

import (
	"context"
	"errors"
	"os"
	"sync"

	"openduck/internal/macosattest"
	"openduck/internal/providerdaemon"
)

type Materialization struct {
	Archive, Target, Manifest, ManifestDigest string
	UID, GID                                  int
}
type Launch struct {
	Identity                                  []byte
	Spec                                      macosattest.HostLaunchSpec
	Qwen                                      *Materialization
	PackageRoot, PackageDigest, ReceiptDigest string
	PackageGID                                uint32
}
type Factory interface {
	Resolve(context.Context, providerdaemon.Request) (Launch, error)
}
type Bridge struct {
	Context  context.Context
	Registry *macosattest.HostRegistry
	Factory  Factory
	mu       sync.Mutex
	sessions map[string]*macosattest.HostProcess
}

func (b *Bridge) Start(ctx context.Context, r providerdaemon.Request) (string, error) {
	if b == nil || b.Context == nil || b.Registry == nil || b.Factory == nil || r.ID == "" {
		return "", providerdaemon.ErrUnavailable
	}
	v, err := b.Factory.Resolve(ctx, r)
	if err != nil {
		return "", err
	}
	if macosattest.VerifyNativePackageCommit(v.PackageRoot, v.Spec.Provider, v.PackageDigest, v.ReceiptDigest, v.PackageGID) != nil {
		return "", providerdaemon.ErrUnavailable
	}
	if v.Qwen != nil {
		q := v.Qwen
		if _, statErr := os.Lstat(q.Target); errors.Is(statErr, os.ErrNotExist) {
			err = macosattest.MaterializeQwenClosure(q.Archive, q.Target, q.Manifest, q.ManifestDigest, q.UID, q.GID)
		} else {
			err = macosattest.VerifyQwenClosure(q.Target, q.Manifest, q.ManifestDigest, uint32(q.UID), uint32(q.GID))
		}
		if err != nil {
			return "", err
		}
	}
	p, err := macosattest.LaunchOfficialHost(b.Context, b.Registry, v.Identity, v.Spec)
	if err != nil {
		return "", err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sessions == nil {
		b.sessions = map[string]*macosattest.HostProcess{}
	}
	if b.sessions[r.ID] != nil {
		_ = p.Stop()
		return "", providerdaemon.ErrConflict
	}
	b.sessions[r.ID] = p
	return r.ID, nil
}
func (b *Bridge) Reconcile(_ context.Context, r providerdaemon.Receipt) (string, providerdaemon.State, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sessions[r.Session] == nil {
		return "", providerdaemon.Terminal, providerdaemon.ErrUnavailable
	}
	return r.Session, providerdaemon.Running, nil
}
func (b *Bridge) Stop(_ context.Context, session string) error {
	b.mu.Lock()
	p := b.sessions[session]
	delete(b.sessions, session)
	b.mu.Unlock()
	if p == nil {
		return nil
	}
	err := p.Stop()
	if errors.Is(err, macosattest.ErrUnavailable) {
		return providerdaemon.ErrUnavailable
	}
	return err
}

var _ providerdaemon.Bridge = (*Bridge)(nil)
