package main

import (
	"errors"
	"time"

	"openduck/internal/macoschannel"
	"openduck/internal/mesh"
	"openduck/internal/providerbridge"
	"openduck/internal/providerrevision"
	"openduck/internal/providertransport"
)

type providerTransportOptions struct {
	enabled              bool
	localRelease         macoschannel.ReleasePin
	uid, gid, channelGID uint32
	keyEpoch             uint64
	numeric              map[string]bool
}

// providerTransportDependencies is a narrow startup seam. Descriptor
// collection occurs before a fixed controller channel exists, so failures
// there must return directly rather than attempting to close an unassigned
// function. The production values remain the fixed providertransport entry
// points; tests use this seam solely to prove that early denial is inert.
type providerTransportDependencies struct {
	descriptorPath func(string) (string, error)
	load           func(providertransport.LoadConfig) (providertransport.Descriptor, error)
	open           func(macoschannel.ReleasePin, uint32, uint32, uint32, uint64, []providertransport.Descriptor) (providertransport.BoundDialer, func(), error)
}

func defaultProviderTransportDependencies() providerTransportDependencies {
	return providerTransportDependencies{descriptorPath: descriptorPath, load: providertransport.Load, open: providertransport.OpenFixedControllerChannel}
}

func openConfiguredProviderTransport(options providerTransportOptions, composition providerCompositionOptions, installed providerrevision.Installed, dependencies providerTransportDependencies) ([]providertransport.Descriptor, providertransport.Dialer, func(), error) {
	if dependencies.descriptorPath == nil || dependencies.load == nil || dependencies.open == nil {
		return nil, nil, nil, errors.New("provider transport dependencies unavailable")
	}
	descriptors := make([]providertransport.Descriptor, 0)
	for _, profile := range installed.Profiles() {
		if !profile.MeshSpawnEnabled {
			continue
		}
		path, err := dependencies.descriptorPath(profile.ID)
		if err != nil {
			// No channel/root has been opened yet, hence there is nothing to
			// close. This direct denial also prevents a nil close-function call.
			return nil, nil, nil, err
		}
		descriptor, err := dependencies.load(providertransport.LoadConfig{RootPath: composition.Root, DescriptorLeaf: path, OwnerUID: composition.OwnerUID, OwnerGID: composition.OwnerGID})
		if err != nil {
			return nil, nil, nil, err
		}
		descriptors = append(descriptors, descriptor)
	}
	dial, closeFn, err := dependencies.open(options.localRelease, options.uid, options.gid, options.channelGID, options.keyEpoch, descriptors)
	if err != nil || closeFn == nil {
		return nil, nil, nil, errors.New("provider transport unavailable")
	}
	return descriptors, dial, closeFn, nil
}

func (o providerTransportOptions) valid() bool {
	return o.enabled && o.uid != 0 && o.gid != 0 && o.channelGID != 0 && o.channelGID != o.gid && o.keyEpoch != 0 && o.localRelease.ReleaseID != "" && o.numeric["provider-transport-controller-uid"] && o.numeric["provider-transport-controller-gid"] && o.numeric["provider-transport-channel-gid"] && o.numeric["provider-transport-key-epoch"] && validPin(o.localRelease)
}
func validPin(p macoschannel.ReleasePin) bool {
	if p.ReleaseID == "" {
		return false
	}
	for _, v := range []string{p.BinaryDigest, p.SocketDigest, p.ManifestDigest} {
		if _, ok := exactDigest(v); !ok {
			return false
		}
	}
	return true
}

func descriptorPath(profile string) (string, error) {
	switch profile {
	case providerbridge.ProfileCodexChatGPT:
		return "codex/runtime-descriptor.json", nil
	case providerbridge.ProfileClaudeCode:
		return "claude/runtime-descriptor.json", nil
	case providerbridge.ProfileQwenGeneral:
		return "qwen/runtime-descriptor.json", nil
	case providerbridge.ProfileKimiCode:
		return "kimi/runtime-descriptor.json", nil
	case providerbridge.ProfileDeepSeekAPI:
		return "deepseek/dsh-adapter-descriptor.json", nil
	default:
		return "", errors.New("no transport descriptor for profile")
	}
}

// newTransportMeshCoordinator is the single composition point at which a
// verified provider revision may acquire an adapter route.  It is deliberately
// separate from startup parsing so tests and the future privileged boundary can
// inject an authenticated macoschannel dialer without exposing it to HTTP/UI.
func newTransportMeshCoordinator(repo mesh.Repository, registry *providerbridge.Registry, installed providerrevision.Installed, descriptors []providertransport.Descriptor, dialer providertransport.Dialer, now time.Time) (*mesh.Coordinator, error) {
	adapters, err := providertransport.NewAdapters(installed, registry, descriptors, dialer, now)
	if err != nil {
		return nil, err
	}
	routes := make([]AttestedSessionAdapter, 0, len(adapters))
	for _, adapter := range adapters {
		routes = append(routes, adapter)
	}
	router, err := newProfileSessionRouter(installed, registry, routes, now)
	if err != nil {
		return nil, err
	}
	directory, err := newProviderMeshDirectory(registry, disabledMeshLimits())
	if err != nil {
		return nil, err
	}
	endpoints, err := mesh.NewPersistentEndpointAuthorizer(repo)
	if err != nil {
		return nil, err
	}
	return mesh.NewCoordinator(mesh.CoordinatorOptions{Repository: repo, Directory: directory, Starter: router, Sessions: router, Endpoints: endpoints, PolicyVersion: "mesh-provider-transport.v1"})
}

// configuredTransportRequired is intentionally strict: an active provider
// revision is not a route.  Startup must receive one validated descriptor for
// every currently enabled profile through the authenticated boundary.
func configuredTransportRequired(installed providerrevision.Installed) bool {
	for _, profile := range installed.Profiles() {
		if profile.MeshSpawnEnabled {
			return true
		}
	}
	return false
}
