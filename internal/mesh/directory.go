package mesh

import (
	"context"
	"sync"
)

// StaticDirectory is a small Controller composition adapter. An installation
// starts with no profiles, so mesh spawning is disabled until an independently
// verified provider registry is deliberately wired in.
type StaticDirectory struct {
	mu       sync.RWMutex
	profiles map[string]Profile
}

func NewStaticDirectory(profiles ...Profile) (*StaticDirectory, error) {
	d := &StaticDirectory{profiles: make(map[string]Profile, len(profiles))}
	for _, p := range profiles {
		if p.Validate() != nil {
			return nil, ErrInvalidContract
		}
		if _, exists := d.profiles[p.ID]; exists {
			return nil, ErrInvalidContract
		}
		d.profiles[p.ID] = p
	}
	return d, nil
}

func (d *StaticDirectory) Lookup(ctx context.Context, id string) (Profile, error) {
	if err := ctx.Err(); err != nil {
		return Profile{}, err
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	p, ok := d.profiles[id]
	if !ok {
		return Profile{}, ErrNotFound
	}
	return p, nil
}
func (d *StaticDirectory) List(ctx context.Context) ([]Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Profile, 0, len(d.profiles))
	for _, p := range d.profiles {
		out = append(out, p)
	}
	return out, nil
}
