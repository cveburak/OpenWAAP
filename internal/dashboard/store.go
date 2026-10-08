package dashboard

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/openwaap/openwaap/internal/events"
)

type Store struct {
	mu            sync.Mutex
	ring          []events.Event
	head          int
	cap           int
	count         int
	now           func() time.Time
	EventsDropped func()
}

func NewStore(capacity int, now func() time.Time) *Store {
	if capacity <= 0 {
		capacity = 10000
	}
	nt := time.Now
	if now != nil {
		nt = now
	}
	return &Store{ring: make([]events.Event, capacity), cap: capacity, now: nt}
}

func (s *Store) Name() string { return "dashboard-store" }

func (s *Store) Emit(_ context.Context, ev events.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ring[s.head] = ev
	s.head = (s.head + 1) % s.cap
	if s.count < s.cap {
		s.count++
	} else if s.EventsDropped != nil {
		s.EventsDropped()
	}
	return nil
}

func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func (s *Store) Recent(limit, offset int, action, ip, rule, category string) []events.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]events.Event, 0, min(limit, s.count))
	skipped := 0
	for i := 0; i < s.count; i++ {
		ev := s.ring[(s.head-1-i+s.cap)%s.cap]
		if action != "" && string(ev.Action) != action {
			continue
		}
		if ip != "" && ev.SourceIP != ip {
			continue
		}
		if rule != "" && ev.RuleID != rule {
			continue
		}
		if category != "" && ev.Category != category {
			continue
		}
		if skipped < offset {
			skipped++
			continue
		}
		out = append(out, ev)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (s *Store) CutOff(since time.Duration) time.Time {
	return s.now().Add(-since)
}

func (s *Store) snapshot(since time.Duration) []events.Event {
	cut := s.CutOff(since)
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []events.Event
	for i := 0; i < s.count; i++ {
		ev := s.ring[(s.head-1-i+s.cap)%s.cap]
		if ev.Timestamp.Before(cut) {
			continue
		}
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.Before(out[j].Timestamp) })
	return out
}

type Count struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

type Summary struct {
	Total        int64 `json:"total"`
	Allowed      int64 `json:"allowed"`
	Blocked      int64 `json:"blocked"`
	Challenged   int64 `json:"challenged"`
	RateLimited  int64 `json:"rate_limited"`
	Throttled    int64 `json:"throttled"`
	Unauthorized int64 `json:"unauthorized"`
	Others       int64 `json:"others"`
}

func SummaryOf(evs []events.Event) Summary {
	var sum Summary
	for _, ev := range evs {
		sum.Total++
		switch ev.Action {
		case events.ActionAllow:
			sum.Allowed++
		case events.ActionBlock:
			sum.Blocked++
		case events.ActionChallenge:
			sum.Challenged++
		case events.ActionRateLimit:
			sum.RateLimited++
		case events.ActionThrottle:
			sum.Throttled++
		case events.ActionUnauthorized:
			sum.Unauthorized++
		default:
			sum.Others++
		}
	}
	return sum
}

func Top(evs []events.Event, field func(events.Event) string, n int) []Count {
	counts := map[string]int{}
	for _, ev := range evs {
		k := field(ev)
		if k == "" {
			k = "(empty)"
		}
		counts[k]++
	}
	return rank(counts, n)
}

func TopStrict(evs []events.Event, field func(events.Event) string, n int) []Count {
	counts := map[string]int{}
	for _, ev := range evs {
		if k := field(ev); k != "" {
			counts[k]++
		}
	}
	return rank(counts, n)
}

func rank(counts map[string]int, n int) []Count {
	out := make([]Count, 0, len(counts))
	for k, v := range counts {
		out = append(out, Count{Label: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Label < out[j].Label
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

type SeriesPoint struct {
	Timestamp    time.Time `json:"timestamp"`
	Total        int       `json:"total"`
	Allowed      int       `json:"allowed"`
	Blocked      int       `json:"blocked"`
	Challenged   int       `json:"challenged"`
	RateLimited  int       `json:"rate_limited"`
	Throttled    int       `json:"throttled"`
	Unauthorized int       `json:"unauthorized"`
	BlockRatio   float64   `json:"block_ratio"`
}

func Series(evs []events.Event, since, bucket time.Duration, now time.Time) []SeriesPoint {
	if len(evs) == 0 {
		return []SeriesPoint{}
	}
	start := now.Add(-since)
	n := int(since.Seconds()/bucket.Seconds()) + 1
	pts := make([]SeriesPoint, n)
	sums := make([]Summary, n)
	for i := range pts {
		pts[i].Timestamp = start.Add(time.Duration(i) * bucket)
	}
	for _, ev := range evs {
		idx := int(ev.Timestamp.Sub(start) / bucket)
		if idx < 0 || idx >= n {
			continue
		}
		s := &sums[idx]
		s.Total++
		switch ev.Action {
		case events.ActionAllow:
			pts[idx].Allowed++
		case events.ActionBlock:
			pts[idx].Blocked++
		case events.ActionChallenge:
			pts[idx].Challenged++
		case events.ActionRateLimit:
			pts[idx].RateLimited++
		case events.ActionThrottle:
			pts[idx].Throttled++
		case events.ActionUnauthorized:
			pts[idx].Unauthorized++
		}
		pts[idx].Total = int(s.Total)
	}
	for i := range pts {
		if pts[i].Total > 0 {
			pts[i].BlockRatio = float64(pts[i].Blocked) / float64(pts[i].Total)
		}
	}
	return pts
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
