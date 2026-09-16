package bootstrap

import (
	"math/rand"
	"sync"
	"time"
)

// ServerBackoff implements the §16.8 reselection timing:
//
//   - first reselection after a failure waits a uniform 0–5s jitter;
//   - repeated failures grow exponentially from a one-second base;
//   - a bound caps the wait so a down server does not mean minutes of
//     silence.
//
// The jitter exists because the design's *other* failure mode — a mass
// outage causing thousands of clients to reselect at once — can only be
// defused by spreading the arrivals, never by removing the trigger.
type ServerBackoff struct {
	jitter time.Duration // uniform width of the initial delay
	base   time.Duration
	max    time.Duration
	factor float64
	rand   *rand.Rand
	mu     sync.Mutex
}

// NewServerBackoff creates the policy with design defaults (§16.8):
// 0–5s initial jitter, 1s base, factor 2, capped at 60s.
func NewServerBackoff() *ServerBackoff {
	return NewServerBackoffWith(5*time.Second, time.Second, 60*time.Second, 2, rand.New(rand.NewSource(time.Now().UnixNano())))
}

// NewServerBackoffWith is the testable constructor (injected source).
func NewServerBackoffWith(jitter, base, max time.Duration, factor float64, src *rand.Rand) *ServerBackoff {
	if base <= 0 {
		base = time.Second
	}
	if max <= 0 {
		max = time.Minute
	}
	return &ServerBackoff{jitter: jitter, base: base, max: max, factor: factor, rand: src}
}

// Delay returns how long to wait before the attempt-th reselection
// (attempt 0 = first failure, which is pure jitter).
func (b *ServerBackoff) Delay(attempt int) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.delayLocked(attempt)
}

func (b *ServerBackoff) delayLocked(attempt int) time.Duration {
	if attempt <= 0 {
		if b.jitter <= 0 {
			return 0
		}
		return time.Duration(b.rand.Int63n(int64(b.jitter)))
	}
	d := float64(b.base)
	for i := 1; i < attempt && d < float64(b.max); i++ {
		d *= b.factor
	}
	if d > float64(b.max) {
		d = float64(b.max)
	}
	if b.jitter > 0 {
		d += float64(b.rand.Int63n(int64(b.jitter)))
	}
	return time.Duration(d)
}

// Picker holds the candidate servers and the current selection. It only
// switches on events (§16.8: healthy connections never migrate because a
// score changed) and tracks the failure count so the backoff can grow.
type Picker struct {
	mu         sync.Mutex
	candidates []string
	current    string
	attempt    int
	backoff    *ServerBackoff
}

// NewPicker builds a picker over the bootstrap address list.
func NewPicker(candidates []string) *Picker {
	p := &Picker{candidates: candidates, backoff: NewServerBackoff()}
	if len(candidates) > 0 {
		p.current = candidates[0]
	}
	return p
}

func NewPickerWith(candidates []string, b *ServerBackoff) *Picker {
	p := &Picker{candidates: candidates, backoff: b}
	if len(candidates) > 0 {
		p.current = candidates[0]
	}
	return p
}

// Current returns the selected server address.
func (p *Picker) Current() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.current
}

// OnSuccess resets the failure counter (a healthy connection heals the
// backoff).
func (p *Picker) OnSuccess() {
	p.mu.Lock()
	p.attempt = 0
	p.mu.Unlock()
}

// OnFailure switches to the next candidate and returns the new address
// plus how long the caller should wait (jitter/backoff) before connecting.
func (p *Picker) OnFailure() (string, time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delay := p.backoff.delayLocked(p.attempt)
	p.attempt++

	if len(p.candidates) == 0 {
		p.current = ""
		return "", delay
	}
	idx := 0
	for i, c := range p.candidates {
		if c == p.current {
			idx = i
			break
		}
	}
	p.current = p.candidates[(idx+1)%len(p.candidates)]
	return p.current, delay
}

// Attempts reports the consecutive failure count.
func (p *Picker) Attempts() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.attempt
}
