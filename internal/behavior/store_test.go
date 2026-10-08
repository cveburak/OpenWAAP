package behavior

import (
	"fmt"
	"testing"
	"time"
)

func TestStoreIdleEviction(t *testing.T) {
	s := NewStore(time.Minute, 1000)
	base := time.Unix(1_700_000_000, 0)

	s.touch("stale-1", base)
	s.touch("stale-2", base)
	s.touch("fresh", base.Add(55*time.Second))

	now := base.Add(90 * time.Second)
	s.touch("trigger", now)

	if got := s.get("stale-1"); got != nil {
		t.Fatal("stale-1 should have been evicted by idle-TTL sweep")
	}
	if got := s.get("stale-2"); got != nil {
		t.Fatal("stale-2 should have been evicted by idle-TTL sweep")
	}
	if got := s.get("fresh"); got == nil {
		t.Fatal("fresh entry should not have been evicted")
	}
}

func TestStoreCapacityBounded(t *testing.T) {
	const max = 50
	s := NewStore(time.Hour, max)
	now := time.Unix(1_700_000_000, 0)

	for i := 0; i < max*4; i++ {
		s.touch(fmt.Sprintf("k%d", i), now)
		s.mu.Lock()
		n := len(s.clients)
		s.mu.Unlock()
		if n > max {
			t.Fatalf("after %d touches: clients map has %d entries, want <= %d", i+1, n, max)
		}
	}
}
