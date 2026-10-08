package dashboard

import (
	"sync"
	"time"
)

type loginThrottle struct {
	max    int
	window time.Duration
	now    func() time.Time
	maxKeys int

	mu   sync.Mutex
	hits map[string][]time.Time
}

const loginThrottleMaxKeys = 20000

func newLoginThrottle(max int, window time.Duration, now func() time.Time) *loginThrottle {
	if now == nil {
		now = time.Now
	}
	return &loginThrottle{
		max: max, window: window, now: now,
		maxKeys: loginThrottleMaxKeys, hits: map[string][]time.Time{},
	}
}

func (t *loginThrottle) allow(ip string) (bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.pruneMapLocked(now)
	at := prune(t.hits[ip], now, t.window)
	if len(at) == 0 {
		delete(t.hits, ip)
	} else {
		t.hits[ip] = at
	}
	if len(at) < t.max {
		return true, 0
	}
	retry := int(at[0].Add(t.window).Sub(now).Seconds())
	if retry < 1 {
		retry = 1
	}
	return false, retry
}

func (t *loginThrottle) record(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.hits[ip] = append(t.hits[ip], t.now())
}

func (t *loginThrottle) reset(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.hits, ip)
}

func (t *loginThrottle) pruneMapLocked(now time.Time) {
	for k, at := range t.hits {
		if len(prune(at, now, t.window)) == 0 {
			delete(t.hits, k)
		}
	}
	if len(t.hits) < t.maxKeys {
		return
	}
	target := t.maxKeys * 9 / 10
	for k := range t.hits {
		if len(t.hits) <= target {
			break
		}
		delete(t.hits, k)
	}
}

func prune(at []time.Time, now time.Time, window time.Duration) []time.Time {
	if len(at) == 0 {
		return at
	}
	cutoff := now.Add(-window)
	i := 0
	for i < len(at) && at[i].Before(cutoff) {
		i++
	}
	return at[i:]
}
