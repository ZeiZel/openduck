package codexruntime

// PlannedRuntimeManifest is the profile that a future launcher is expected to
// request. It is deliberately not a runtime attestation: no caller can label
// an unobserved process as having these properties.
type PlannedRuntimeManifest struct {
	Profile       Profile
	ProfileDigest string
}

func BuildPlannedRuntimeManifest(readRoots, writeRoots []string) (PlannedRuntimeManifest, error) {
	p, digest, err := GenerateProfile(readRoots, writeRoots)
	if err != nil {
		return PlannedRuntimeManifest{}, err
	}
	return PlannedRuntimeManifest{Profile: p, ProfileDigest: digest}, nil
}
