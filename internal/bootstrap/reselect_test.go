package bootstrap

import (
	"math/rand"
	"testing"
	"time"
)

// TestPickerEventDrivenOnly checks §16.8: the picker never migrates on its
// own — current stays put until OnFailure fires.
func TestPickerEventDrivenOnly(t *testing.T) {
	p := NewPicker([]string{"s1", "s2", "s3"})
	if p.Current() != "s1" {
		t.Fatalf("initial = %s, want s1", p.Current())
	}
	// No event → no migration.
	if p.Current() != "s1" {
		t.Error("picker migrated without an event")
	}
	// One failure → moves to s2, one attempt recorded.
	next, delay := p.OnFailure()
	if next != "s2" {
		t.Errorf("after one failure: got %s, want s2", next)
	}
	if delay < 0 {
		t.Errorf("delay must be non-negative, got %v", delay)
	}
	if p.Attempts() != 1 {
		t.Errorf("attempts = %d, want 1", p.Attempts())
	}
}

// TestPickerWrapsAround checks the candidate ring.
func TestPickerWrapsAround(t *testing.T) {
	p := NewPicker([]string{"s1", "s2"})
	p.OnFailure() // → s2
	p.OnFailure() // → s1 (wrap)
	if p.Current() != "s1" {
		t.Errorf("after wrap: got %s, want s1", p.Current())
	}
}

// TestPickerOnSuccessResetsBackoff checks a healthy connection heals the
// failure count.
func TestPickerOnSuccessResetsBackoff(t *testing.T) {
	p := NewPicker([]string{"a", "b"})
	p.OnFailure()
	p.OnFailure()
	if p.Attempts() != 2 {
		t.Fatalf("attempts = %d, want 2", p.Attempts())
	}
	p.OnSuccess()
	if p.Attempts() != 0 {
		t.Errorf("attempts after success = %d, want 0", p.Attempts())
	}
}

// TestBackoffShapes checks the §16.8 curve: first failure is pure 0–5s
// jitter, later failures grow exponentially and stay under the cap.
func TestBackoffShapes(t *testing.T) {
	b := NewServerBackoffWith(5*time.Second, time.Second, 60*time.Second, 2, rand.New(rand.NewSource(1)))

	// Attempt 0: bounded by jitter.
	for i := 0; i < 100; i++ {
		if d := b.Delay(0); d < 0 || d >= 5*time.Second {
			t.Fatalf("jitter delay out of range: %v", d)
		}
	}
	// Successive attempts grow: expect delay(0) < delay(3).
	var zero, three time.Duration
	zero = b.Delay(0)
	three = b.Delay(3)
	if three <= zero {
		t.Errorf("backoff must grow: delay(0)=%v delay(3)=%v", zero, three)
	}
	// Cap holds: exponential part is capped at 60s, plus up to 5s of jitter.
	if d := b.Delay(20); d > 65*time.Second {
		t.Errorf("backoff exceeded cap: %v", d)
	}
}

// TestBackoffDeterministicWithFixedSource checks determinism when the
// random source is pinned — reselection timing must be reproducible in
// tests and audits.
func TestBackoffDeterministicWithFixedSource(t *testing.T) {
	a := NewServerBackoffWith(5*time.Second, time.Second, 60*time.Second, 2, rand.New(rand.NewSource(42)))
	b := NewServerBackoffWith(5*time.Second, time.Second, 60*time.Second, 2, rand.New(rand.NewSource(42)))
	for i := 0; i < 10; i++ {
		if a.Delay(i) != b.Delay(i) {
			t.Fatalf("same seed, different delays at attempt %d", i)
		}
	}
}
