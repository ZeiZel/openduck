package syntheticadmission

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"openduck/internal/admission"
)

// KeychainCheckpoint is a cooperative durable checkpoint adapter. It is not
// an attested security authority against another process running as the same
// UID, and therefore cannot mint a production admission checkpoint.
// Only version and ledger digest are stored; no runtime key or payload is
// written. A fixed service/account prevents arbitrary namespace selection.
type KeychainCheckpoint struct{ mu sync.Mutex }

const checkpointService = "openduck.synthetic.admission"
const checkpointAccount = "ledger-checkpoint"

func NewKeychainCheckpoint() *KeychainCheckpoint { return &KeychainCheckpoint{} }
func (k *KeychainCheckpoint) LoadCheckpoint() (admission.LedgerCheckpoint, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.load()
}
func (k *KeychainCheckpoint) CommitCheckpoint(expected uint64, next admission.LedgerCheckpoint) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	lock, err := os.OpenFile("/tmp/openduck-synthetic-checkpoint.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return admission.ErrCheckpointUnavailable
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return admission.ErrCheckpointUnavailable
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	cur, err := k.load()
	if err != nil {
		return err
	}
	if cur.Version != expected || next.Version != expected+1 || next.StateDigest == "" {
		return admission.ErrCheckpointMismatch
	}
	b, _ := json.Marshal(next)
	cmd := exec.Command("/usr/bin/security", "add-generic-password", "-s", checkpointService, "-a", checkpointAccount, "-w", string(b), "-U")
	if err := cmd.Run(); err != nil {
		return admission.ErrCheckpointUnavailable
	}
	return nil
}
func (k *KeychainCheckpoint) load() (admission.LedgerCheckpoint, error) {
	out, err := exec.Command("/usr/bin/security", "find-generic-password", "-s", checkpointService, "-a", checkpointAccount, "-w").CombinedOutput()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok && strings.TrimSpace(string(out)) == "SecKeychainSearchCopyNext: The specified item could not be found in the keychain." {
			return admission.LedgerCheckpoint{}, nil
		}
		return admission.LedgerCheckpoint{}, admission.ErrCheckpointUnavailable
	}
	var cp admission.LedgerCheckpoint
	if json.Unmarshal(out, &cp) != nil {
		return admission.LedgerCheckpoint{}, errors.New("invalid keychain checkpoint")
	}
	return cp, nil
}
