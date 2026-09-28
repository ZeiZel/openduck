package codexruntime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"openduck/internal/codexbroker"
	"openduck/internal/modelegress"
)

type brokerBackendProcess struct {
	mu         sync.Mutex
	reads      []string
	terminated bool
	joined     bool
}

func (p *brokerBackendProcess) Read(dst []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.reads) == 0 {
		return 0, errors.New("test process exhausted")
	}
	n := copy(dst, p.reads[0])
	if n == len(p.reads[0]) {
		p.reads = p.reads[1:]
	} else {
		p.reads[0] = p.reads[0][n:]
	}
	return n, nil
}
func (p *brokerBackendProcess) Write(src []byte) (int, error) { return len(src), nil }
func (p *brokerBackendProcess) Close() error                  { return nil }
func (p *brokerBackendProcess) terminate() error {
	p.mu.Lock()
	p.terminated = true
	p.mu.Unlock()
	return nil
}
func (p *brokerBackendProcess) wait() error {
	p.mu.Lock()
	p.joined = true
	p.mu.Unlock()
	return nil
}

type blockedWaitProcess struct {
	stop chan struct{}
}

func (p *blockedWaitProcess) Read([]byte) (int, error)    { return 0, errors.New("blocked test process") }
func (p *blockedWaitProcess) Write(b []byte) (int, error) { return len(b), nil }
func (p *blockedWaitProcess) Close() error                { return nil }
func (p *blockedWaitProcess) terminate() error            { return nil }
func (p *blockedWaitProcess) wait() error                 { <-p.stop; return nil }

type brokerBackendIsolation struct {
	process *brokerBackendProcess
	att     codexbroker.BoundaryAttestation
}

type expiredGrantIsolation struct {
	brokerBackendIsolation
	starts int
}

func (i *expiredGrantIsolation) proxyAddress(context.Context) (string, error) {
	return "", ErrProductionIsolationConfig
}
func (i *expiredGrantIsolation) start(context.Context) (ProductionRuntimeProcess, error) {
	i.starts++
	return i.process, nil
}

func (i *brokerBackendIsolation) start(context.Context) (ProductionRuntimeProcess, error) {
	return i.process, nil
}
func (i *brokerBackendIsolation) attestation(context.Context) (codexbroker.BoundaryAttestation, error) {
	return i.att, nil
}
func (i *brokerBackendIsolation) modelCapability(context.Context) (modelegress.ProductionCapability, error) {
	return nil, modelegress.ErrNoCapability
}

func TestProductionBackendRefusesUnverifiedModelCapability(t *testing.T) {
	identity := codexbroker.ExpectedRuntimeIdentity{RuntimeID: "runtime_1", BrokerBinaryDigest: codexbroker.Digest("broker"), RuntimeBinaryDigest: codexbroker.Digest("runtime"), PolicyDigest: codexbroker.Digest("policy"), BrokerReleaseDigest: codexbroker.Digest("release"), BrokerSocketDigest: codexbroker.Digest("socket"), PeerUID: 1000, PeerGID: 1000, RuntimeUID: 1001, RuntimeGID: 1001, ExpectedEgressUID: 1002, ExpectedEgressGID: 1002, ExpectedEgressReleaseDigest: codexbroker.Digest("egress-release"), ExpectedEgressSocketDigest: codexbroker.Digest("egress-socket"), KeyEpoch: 1, Channel: "codex-control", LocalRole: "broker", PeerRole: "controller", BindingDigest: codexbroker.Digest("binding")}
	b, err := NewProductionBackend(identity, &brokerBackendIsolation{}, "gpt-5.6-sol")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Inventory(context.Background()); !errors.Is(err, ErrRuntimeIsolationRequired) {
		t.Fatalf("unverified capability err=%v", err)
	}
}

func TestProductionBackendExpiredGrantNeverStartsLazyChild(t *testing.T) {
	identity := codexbroker.ExpectedRuntimeIdentity{RuntimeID: "runtime_1", BrokerBinaryDigest: codexbroker.Digest("broker"), RuntimeBinaryDigest: codexbroker.Digest("runtime"), PolicyDigest: codexbroker.Digest("policy"), BrokerReleaseDigest: codexbroker.Digest("release"), BrokerSocketDigest: codexbroker.Digest("socket"), PeerUID: 1000, PeerGID: 1000, RuntimeUID: 1001, RuntimeGID: 1001, ExpectedEgressUID: 1002, ExpectedEgressGID: 1002, ExpectedEgressReleaseDigest: codexbroker.Digest("egress-release"), ExpectedEgressSocketDigest: codexbroker.Digest("egress-socket"), KeyEpoch: 1, Channel: "runtime-channel", LocalRole: "runtime", PeerRole: "broker", BindingDigest: codexbroker.Digest("binding")}
	for _, call := range []struct {
		name string
		run  func(*ProductionBackend) error
	}{
		{name: "inventory", run: func(b *ProductionBackend) error { _, err := b.Inventory(context.Background()); return err }},
		{name: "login", run: func(b *ProductionBackend) error {
			_, err := b.LoginStart(context.Background(), codexbroker.LoginStart{AccountType: "chatgpt"})
			return err
		}},
	} {
		t.Run(call.name, func(t *testing.T) {
			iso := &expiredGrantIsolation{brokerBackendIsolation: brokerBackendIsolation{process: &brokerBackendProcess{}}}
			b, err := NewProductionBackend(identity, iso, "gpt-5.6-sol")
			if err != nil {
				t.Fatal(err)
			}
			if err := call.run(b); !errors.Is(err, ErrRuntimeIsolationRequired) {
				t.Fatalf("expired grant err=%v", err)
			}
			if iso.starts != 0 {
				t.Fatalf("expired grant started child %d times", iso.starts)
			}
		})
	}
}

func TestProductionEgressBindingKeepsPrincipalsDistinct(t *testing.T) {
	e := codexbroker.ExpectedRuntimeIdentity{RuntimeID: "r", BrokerBinaryDigest: codexbroker.Digest("broker"), RuntimeBinaryDigest: codexbroker.Digest("r"), PolicyDigest: codexbroker.Digest("p"), BrokerReleaseDigest: codexbroker.Digest("rel"), BrokerSocketDigest: codexbroker.Digest("sock"), PeerUID: 1, PeerGID: 2, RuntimeUID: 3, RuntimeGID: 4, ExpectedEgressUID: 5, ExpectedEgressGID: 6, ExpectedEgressReleaseDigest: codexbroker.Digest("er"), ExpectedEgressSocketDigest: codexbroker.Digest("es"), KeyEpoch: 1, Channel: "c", LocalRole: "a", PeerRole: "b", BindingDigest: codexbroker.Digest("b")}
	b, err := productionEgressBinding(e)
	if err != nil || b.UID != 5 || b.GID != 6 {
		t.Fatalf("egress binding=%+v err=%v", b, err)
	}
	e.ExpectedEgressUID, e.ExpectedEgressGID = e.RuntimeUID, e.RuntimeGID
	if _, err := productionEgressBinding(e); !errors.Is(err, ErrRuntimeIsolationRequired) {
		t.Fatalf("conflated principals accepted: %v", err)
	}
}

func TestProductionBackendRefusesMissingIsolation(t *testing.T) {
	if _, err := NewProductionBackend(codexbroker.ExpectedRuntimeIdentity{}, nil, "gpt-5.6-sol"); !errors.Is(err, ErrRuntimeIsolationRequired) {
		t.Fatalf("missing isolation err=%v", err)
	}
}

func TestProductionBackendShutdownIsBoundedAndIdempotent(t *testing.T) {
	p := &blockedWaitProcess{stop: make(chan struct{})}
	b := &ProductionBackend{state: backendReady, process: newRuntimeHandle(p)}
	started := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		close(started)
		results <- b.Cancel(context.Background(), codexbroker.Cancel{SessionID: "s", TurnID: "t"})
	}()
	<-started
	go func() { results <- b.Close(context.Background()) }()
	deadline := time.NewTimer(productionShutdownTimeout + time.Second)
	defer deadline.Stop()
	for range 2 {
		select {
		case <-results:
		case <-deadline.C:
			t.Fatal("concurrent shutdown hung")
		}
	}
	close(p.stop)
}

func TestProductionBackendStoppingStateBlocksSecondLaunch(t *testing.T) {
	b := &ProductionBackend{state: backendStopping, generation: 7}
	if _, _, err := b.ensureProcess(context.Background()); !errors.Is(err, codexbroker.ErrClosed) {
		t.Fatalf("stopping backend launched a second child: %v", err)
	}
}

func TestProductionBackendSecondCancelCannotOwnStop(t *testing.T) {
	p := &blockedWaitProcess{stop: make(chan struct{})}
	b := &ProductionBackend{state: backendReady, process: newRuntimeHandle(p)}
	first := make(chan error, 1)
	go func() { first <- b.Cancel(context.Background(), codexbroker.Cancel{SessionID: "s", TurnID: "t"}) }()
	deadline := time.NewTimer(100 * time.Millisecond)
	defer deadline.Stop()
	for {
		b.mu.Lock()
		stopping := b.state == backendStopping
		b.mu.Unlock()
		if stopping {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("first cancel did not claim stop")
		default:
		}
		time.Sleep(time.Millisecond)
	}
	if err := b.Cancel(context.Background(), codexbroker.Cancel{SessionID: "s", TurnID: "t"}); !errors.Is(err, ErrRuntimeState) {
		t.Fatalf("second cancel became stop owner: %v", err)
	}
	close(p.stop)
	if err := <-first; err != nil {
		t.Fatalf("first cancel err=%v", err)
	}
}

func TestProductionBackendCloseCannotClaimStoppingOwner(t *testing.T) {
	p := &blockedWaitProcess{stop: make(chan struct{})}
	b := &ProductionBackend{state: backendReady, process: newRuntimeHandle(p)}
	first := make(chan error, 1)
	go func() { first <- b.Cancel(context.Background(), codexbroker.Cancel{SessionID: "s", TurnID: "t"}) }()
	deadline := time.NewTimer(100 * time.Millisecond)
	defer deadline.Stop()
	for {
		b.mu.Lock()
		stopping := b.state == backendStopping
		b.mu.Unlock()
		if stopping {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("cancel did not claim stop")
		default:
		}
		time.Sleep(time.Millisecond)
	}
	if err := b.Close(context.Background()); !errors.Is(err, ErrRuntimeState) {
		t.Fatalf("close claimed stop before join: %v", err)
	}
	if b.state == backendClosed {
		t.Fatal("close marked backend closed before owner join")
	}
	close(p.stop)
	if err := <-first; err != nil {
		t.Fatalf("cancel err=%v", err)
	}
}
