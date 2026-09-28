// openduck-codex-login is a device-code bootstrap helper. It speaks only to
// the authenticated broker and emits URL/code; tokens and broker-owned auth
// files never cross this command boundary.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"openduck/internal/codexbroker"
	"openduck/internal/macoschannel"
	"openduck/internal/servicekey"
	"openduck/internal/verifiedroot"
)

type output struct {
	AuthorizationURL string `json:"authorization_url,omitempty"`
	UserCode         string `json:"user_code,omitempty"`
}

type loginOptions struct {
	production                                                                               bool
	channel, socketRoot, releaseRoot, keyRoot, keyFile, socket, binaryName                   string
	proofFile, releaseID                                                                     string
	localRelease, brokerRelease, runtimeID, runtimeDigest, policyDigest                      string
	brokerBinaryDigest, releaseDigest, socketDigest, egressReleaseDigest, egressSocketDigest string
	localUID, localGID, brokerUID, brokerGID, egressUID, egressGID, channelGID               uint
	epoch                                                                                    uint64
}

type loginDependencies struct {
	open      func([]verifiedroot.Requirement) ([]verifiedroot.Root, error)
	dial      func(context.Context, *macoschannel.Dialer) (macoschannel.Conn, error)
	connector func(macoschannel.Conn, codexbroker.ExpectedRuntimeIdentity) (*codexbroker.ProductionConnector, error)
}

func productionLoginDependencies() loginDependencies {
	return loginDependencies{open: verifiedroot.OpenAll, dial: func(ctx context.Context, d *macoschannel.Dialer) (macoschannel.Conn, error) { return d.Dial(ctx) }, connector: codexbroker.NewProductionConnector}
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string, out interface{ Write([]byte) (int, error) }) error {
	o, err := parseLoginOptions(args)
	if err != nil {
		return err
	}
	return runLogin(context.Background(), o, out, productionLoginDependencies())
}

func parseLoginOptions(args []string) (loginOptions, error) {
	fs := flag.NewFlagSet("openduck-codex-login", flag.ContinueOnError)
	var o loginOptions
	fs.BoolVar(&o.production, "production-admission", false, "require authenticated broker composition")
	fs.StringVar(&o.channel, "channel", "", "exact broker channel")
	fs.StringVar(&o.socketRoot, "socket-root", "", "shared channel root")
	fs.StringVar(&o.releaseRoot, "release-root", "", "Controller release root")
	fs.StringVar(&o.keyRoot, "key-root", "", "Controller key root")
	fs.StringVar(&o.keyFile, "key-file", "", "key leaf")
	fs.StringVar(&o.socket, "socket", "owner.sock", "broker socket leaf")
	fs.StringVar(&o.binaryName, "binary-name", "", "Controller binary leaf")
	fs.StringVar(&o.proofFile, "proof-file", "", "fixed nonsecret login proof path")
	fs.StringVar(&o.releaseID, "release-id", "", "active release id")
	fs.StringVar(&o.localRelease, "local-release", "", "Controller release pin JSON")
	fs.StringVar(&o.brokerRelease, "broker-release", "", "broker release pin JSON")
	fs.StringVar(&o.runtimeID, "runtime-id", "", "runtime identity")
	fs.StringVar(&o.runtimeDigest, "runtime-digest", "", "runtime binary digest")
	fs.StringVar(&o.brokerBinaryDigest, "broker-binary-digest", "", "broker binary digest")
	fs.StringVar(&o.policyDigest, "policy-digest", "", "egress policy digest")
	fs.StringVar(&o.releaseDigest, "release-digest", "", "broker release digest")
	fs.StringVar(&o.socketDigest, "socket-digest", "", "broker socket digest")
	fs.StringVar(&o.egressReleaseDigest, "egress-release-digest", "", "egress release digest")
	fs.StringVar(&o.egressSocketDigest, "egress-socket-digest", "", "egress socket digest")
	fs.UintVar(&o.localUID, "local-uid", 0, "Controller uid")
	fs.UintVar(&o.localGID, "local-gid", 0, "Controller gid")
	fs.UintVar(&o.brokerUID, "broker-uid", 0, "broker uid")
	fs.UintVar(&o.brokerGID, "broker-gid", 0, "broker gid")
	fs.UintVar(&o.egressUID, "egress-uid", 0, "egress uid")
	fs.UintVar(&o.egressGID, "egress-gid", 0, "egress gid")
	fs.UintVar(&o.channelGID, "channel-gid", 0, "shared channel gid")
	fs.Uint64Var(&o.epoch, "epoch", 0, "key epoch")
	if err := fs.Parse(args); err != nil {
		return loginOptions{}, err
	}
	if fs.NArg() != 0 || !o.production {
		return loginOptions{}, errors.New("production mode is required; login is disabled")
	}
	if err := o.validate(); err != nil {
		return loginOptions{}, err
	}
	return o, nil
}
func (o loginOptions) validate() error {
	for _, p := range []string{o.socketRoot, o.releaseRoot, o.keyRoot} {
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p || p == string(filepath.Separator) {
			return errors.New("authenticated broker channel required")
		}
	}
	for _, v := range []string{o.channel, o.keyFile, o.socket, o.binaryName, o.proofFile, o.releaseID, o.localRelease, o.brokerRelease, o.runtimeID, o.runtimeDigest, o.brokerBinaryDigest, o.policyDigest, o.releaseDigest, o.socketDigest, o.egressReleaseDigest, o.egressSocketDigest} {
		if v == "" {
			return errors.New("authenticated broker channel required")
		}
	}
	if filepath.Base(o.socket) != o.socket || o.localUID == 0 || o.localGID == 0 || o.brokerUID == 0 || o.brokerGID == 0 || o.egressUID == 0 || o.egressGID == 0 || o.channelGID == 0 || o.epoch == 0 {
		return errors.New("authenticated broker channel required")
	}
	if o.proofFile != "/Library/Application Support/OpenDuck/state/controller/login-proof.json" || filepath.Clean(o.proofFile) != o.proofFile {
		return errors.New("authenticated broker channel required")
	}
	return nil
}

// runLogin owns the channel lifetime. The broker's correlated completion
// notification is awaited after the device data has been printed; auth state
// remains solely in the broker-owned CODEX_HOME.
func runLogin(ctx context.Context, o loginOptions, out interface{ Write([]byte) (int, error) }, d loginDependencies) error {
	if d.open == nil || d.dial == nil || d.connector == nil {
		return errors.New("authenticated broker channel required")
	}
	var local, broker macoschannel.ReleasePin
	if err := loadJSON(o.localRelease, &local); err != nil {
		return err
	}
	if err := loadJSON(o.brokerRelease, &broker); err != nil {
		return err
	}
	if "sha256:"+broker.ManifestDigest != o.releaseDigest || "sha256:"+broker.SocketDigest != o.socketDigest {
		return errors.New("broker release pin mismatch")
	}
	roots, err := d.open([]verifiedroot.Requirement{{Name: "Controller socket", Path: o.socketRoot, UID: uint32(o.brokerUID), GID: uint32(o.channelGID), Mode: 0750}, {Name: "Controller release", Path: o.releaseRoot, UID: 0, GID: uint32(o.localGID), Mode: 0550}, {Name: "Controller key", Path: o.keyRoot, UID: uint32(o.localUID), GID: uint32(o.localGID), Mode: 0700}})
	if err != nil {
		return err
	}
	defer verifiedroot.CloseAll(roots)
	if len(roots) != 3 {
		return errors.New("authenticated broker channel required")
	}
	key, err := servicekey.New(roots[2].Handle(), servicekey.Policy{FileName: o.keyFile, Channel: o.channel, OwnerUID: uint32(o.localUID), OwnerGID: uint32(o.localGID), Mode: 0600, RootUID: uint32(o.localUID), RootGID: uint32(o.localGID), RootMode: 0700})
	if err != nil {
		return err
	}
	uid, gid := uint32(o.brokerUID), uint32(o.brokerGID)
	cfg := macoschannel.Config{Contract: macoschannel.SocketContract{Channel: o.channel, LocalRole: "controller", PeerRole: "broker", SocketPath: o.socket, SocketRoot: o.socketRoot, ExpectedPeerUID: &uid, ExpectedPeerGID: &gid, ExpectedSocketRootUID: uid, ExpectedSocketRootGID: uint32(o.channelGID), ExpectedSocketRootMode: 0750, ExpectedSocketUID: uid, ExpectedSocketGID: uint32(o.channelGID), ExpectedSocketMode: 0660}, LocalRelease: local, PeerRelease: broker, ReleaseRoot: roots[1].Handle(), SocketRootFD: roots[0].Handle(), BinaryName: o.binaryName, KeySource: key, ExpectedReleaseRootUID: 0, ExpectedReleaseRootGID: uint32(o.localGID), ExpectedReleaseRootMode: 0550, ExpectedManifestMode: 0440, ExpectedBinaryMode: 0550}
	dialer, err := macoschannel.NewDialer(cfg)
	if err != nil {
		return err
	}
	conn, err := d.dial(ctx, dialer)
	if err != nil {
		return err
	}
	defer conn.Close()
	identity := codexbroker.ExpectedRuntimeIdentity{RuntimeID: o.runtimeID, BrokerBinaryDigest: o.brokerBinaryDigest, RuntimeBinaryDigest: o.runtimeDigest, PolicyDigest: o.policyDigest, BrokerReleaseDigest: o.releaseDigest, BrokerSocketDigest: o.socketDigest, PeerUID: uint32(o.localUID), PeerGID: uint32(o.localGID), RuntimeUID: uint32(o.brokerUID), RuntimeGID: uint32(o.brokerGID), ExpectedEgressUID: uint32(o.egressUID), ExpectedEgressGID: uint32(o.egressGID), ExpectedEgressReleaseDigest: o.egressReleaseDigest, ExpectedEgressSocketDigest: o.egressSocketDigest, KeyEpoch: o.epoch, Channel: o.channel, LocalRole: "broker", PeerRole: "controller"}
	identity.BindingDigest = identity.ComputeBindingDigest(conn.Evidence())
	if identity.BindingDigest == "" {
		return errors.New("authenticated broker channel required")
	}
	connector, err := d.connector(conn, identity)
	if err != nil {
		return err
	}
	client, err := connector.Client()
	if err != nil {
		return err
	}
	defer client.Close(context.Background())
	if err := runWithClient(ctx, client, out); err != nil {
		return err
	}
	return writeLoginProof(o)
}

func writeLoginProof(o loginOptions) error {
	proof := struct {
		Schema              string `json:"schema"`
		ReleaseID           string `json:"release_id"`
		RuntimeID           string `json:"runtime_id"`
		BrokerReleaseDigest string `json:"broker_release_digest"`
		Completed           bool   `json:"completed"`
	}{"openduck-login-proof.v1", o.releaseID, o.runtimeID, strings.TrimPrefix(o.releaseDigest, "sha256:"), true}
	b, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(o.proofFile)
	tmp, err := os.CreateTemp(dir, ".login-proof-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(b)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, o.proofFile); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	_ = d.Close()
	return err
}

func loadJSON(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}
func runWithClient(ctx context.Context, client codexbroker.OwnerRuntimeClient, out interface{ Write([]byte) (int, error) }) error {
	if client == nil {
		return errors.New("authenticated broker channel required")
	}
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	v, err := client.LoginStart(callCtx, codexbroker.LoginStart{AccountType: "chatgptDeviceCode"})
	if err != nil {
		return err
	}
	if v.Validate() != nil {
		return errors.New("invalid device-code response from broker")
	}
	b, err := json.Marshal(output{AuthorizationURL: v.AuthorizationURL, UserCode: v.UserCode})
	if err != nil {
		return err
	}
	_, err = out.Write(append(b, '\n'))
	if err != nil {
		return err
	}
	completionCtx, completionCancel := context.WithTimeout(ctx, 10*time.Minute)
	defer completionCancel()
	completed, err := client.LoginCompleted(completionCtx, v.LoginID)
	if err != nil {
		return err
	}
	if completed.Validate() != nil || completed.LoginID != v.LoginID || !completed.Success {
		return errors.New("broker login completion unavailable")
	}
	return nil
}
