package reputation

import (
	"sync"
	"testing"
	"time"
)

func TestObserveAndScore(t *testing.T) {
	s := New(nil)
	s.Observe("1.2.3.4", 25)
	s.Observe("1.2.3.4", 25)
	if got := s.Score("1.2.3.4"); got != 50 {
		t.Fatalf("expected 50, got %d", got)
	}
	if got := s.Score("9.9.9.9"); got != 0 {
		t.Fatalf("unknown IP should score 0, got %d", got)
	}
}

func TestCappedAt100(t *testing.T) {
	s := New(nil)
	for i := 0; i < 10; i++ {
		s.Observe("5.5.5.5", 50)
	}
	if got := s.Score("5.5.5.5"); got != 100 {
		t.Fatalf("expected cap 100, got %d", got)
	}
}

func TestDecay(t *testing.T) {
	base := time.Now()
	now := base
	s := New(func() time.Time { return now })
	s.Observe("1.2.3.4", 60)
	now = base.Add(45 * time.Second)
	if got := s.Score("1.2.3.4"); got >= 60 {
		t.Fatalf("expected decayed score < 60, got %d", got)
	}
	now = base.Add(24 * time.Hour)
	if got := s.Score("1.2.3.4"); got != 0 {
		t.Fatalf("expected full decay to 0, got %d", got)
	}
}

func TestObserveIgnoresEmpty(t *testing.T) {
	s := New(nil)
	s.Observe("", 50)
	s.Observe("10.0.0.1", 0)
	if s.Score("10.0.0.1") != 0 {
		t.Fatal("points<=0 must be ignored")
	}
}

func TestPrune(t *testing.T) {
	base := time.Now()
	now := base
	s := New(func() time.Time { return now })
	s.Observe("1.1.1.1", 10)
	s.Prune(3 * time.Minute)
	if s.Score("1.1.1.1") == 0 {
		t.Fatal("entry with score>0 must not be pruned")
	}
	now = base.Add(24 * time.Hour)
	s.Prune(3 * time.Minute)
	now = base.Add(25 * time.Hour)
	s.Prune(3 * time.Minute)
	s.mu.Lock()
	_, ok := s.m["1.1.1.1"]
	s.mu.Unlock()
	if ok {
		t.Fatal("decayed idle entry should be pruned")
	}
}

func TestConcurrent(t *testing.T) {
	s := New(nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				s.Observe("3.3.3.3", 1)
				_ = s.Score("3.3.3.3")
			}
		}()
	}
	wg.Wait()
	if got := s.Score("3.3.3.3"); got <= 0 || got > 100 {
		t.Fatalf("score out of range: %d", got)
	}
}
