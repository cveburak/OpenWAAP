package dashboard

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/events"
)

func ev(action events.Action, ip, path string, ts time.Time) events.Event {
	return events.Event{Timestamp: ts, SourceIP: ip, Path: path, Action: action, RuleID: "r1"}
}

func TestStoreRingEvictionAndOrder(t *testing.T) {
	now := time.Now()
	s := NewStore(3, func() time.Time { return now })
	for i := 0; i < 5; i++ {
		s.Emit(context.Background(), ev(events.ActionAllow, "1.1.1.1", "/a", now))
	}
	if got := s.Len(); got != 3 {
		t.Fatalf("ring should hold 3, got %d", got)
	}
	recent := s.Recent(10, 0, "", "", "", "")
	if len(recent) != 3 {
		t.Fatalf("want 3 events, got %d", len(recent))
	}
}

func TestStoreRecentFilterAndLimit(t *testing.T) {
	now := time.Now()
	s := NewStore(16, func() time.Time { return now })
	s.Emit(context.Background(), ev(events.ActionBlock, "1.1.1.1", "/bad", now))
	s.Emit(context.Background(), ev(events.ActionAllow, "2.2.2.2", "/ok", now.Add(time.Second)))
	s.Emit(context.Background(), ev(events.ActionBlock, "3.3.3.3", "/bad", now.Add(2*time.Second)))

	blocks := s.Recent(10, 0, string(events.ActionBlock), "", "", "")
	if len(blocks) != 2 {
		t.Fatalf("want 2 blocked events, got %d", len(blocks))
	}
	if !strings.HasPrefix(blocks[0].SourceIP, "3.3.3.3") {
		t.Fatalf("newest first, got %s", blocks[0].SourceIP)
	}

	one := s.Recent(1, 0, "", "", "", "")
	if len(one) != 1 {
		t.Fatalf("limit not applied")
	}
}

func TestSummaryTopSeries(t *testing.T) {
	now := time.Now()
	var evs []events.Event
	evs = append(evs, ev(events.ActionBlock, "1.1.1.1", "/a", now))
	evs = append(evs, ev(events.ActionBlock, "1.1.1.1", "/b", now))
	evs = append(evs, ev(events.ActionAllow, "2.2.2.2", "/a", now))
	evs = append(evs, ev(events.ActionChallenge, "3.3.3.3", "/c", now))
	evs = append(evs, ev(events.ActionRateLimit, "4.4.4.4", "/a", now))

	sum := SummaryOf(evs)
	if sum.Total != 5 || sum.Blocked != 2 || sum.Allowed != 1 || sum.Challenged != 1 || sum.RateLimited != 1 {
		t.Fatalf("summary mismatch: %+v", sum)
	}

	ips := Top(evs, func(e events.Event) string { return e.SourceIP }, 2)
	if len(ips) != 2 || ips[0].Label != "1.1.1.1" || ips[0].Count != 2 {
		t.Fatalf("top ips mismatch: %+v", ips)
	}

	paths := Top(evs, func(e events.Event) string { return e.Path }, 10)
	if len(paths) != 3 {
		t.Fatalf("want 3 paths, got %+v", paths)
	}

	sr := Series(evs, time.Minute, 15*time.Second, now.Add(30*time.Second))
	if len(sr) == 0 {
		t.Fatal("series empty")
	}
	var total int
	for _, p := range sr {
		total += p.Total
	}
	if total != 5 {
		t.Fatalf("series should sum to 5, got %d", total)
	}
}

func TestStoreRecentCompositeFilters(t *testing.T) {
	now := time.Now()
	s := NewStore(32, func() time.Time { return now })
	emit := func(action events.Action, ip, rule, category string) {
		s.Emit(context.Background(), events.Event{
			Timestamp: now, SourceIP: ip, RuleID: rule, Category: category, Action: action,
		})
	}
	emit(events.ActionBlock, "5.5.5.5", "sqli-001", "SQL_INJECTION")
	emit(events.ActionBlock, "5.5.5.5", "xss-002", "XSS")
	emit(events.ActionAllow, "6.6.6.6", "", "")

	if got := s.Recent(10, 0, "", "5.5.5.5", "", ""); len(got) != 2 {
		t.Fatalf("ip filter: want 2, got %d", len(got))
	}
	if got := s.Recent(10, 0, "", "", "xss-002", ""); len(got) != 1 || got[0].RuleID != "xss-002" {
		t.Fatalf("rule filter: got %+v", got)
	}
	if got := s.Recent(10, 0, "", "", "", "SQL_INJECTION"); len(got) != 1 || got[0].Category != "SQL_INJECTION" {
		t.Fatalf("category filter: got %+v", got)
	}
	if got := s.Recent(10, 0, string(events.ActionAllow), "6.6.6.6", "", ""); len(got) != 1 {
		t.Fatalf("combined filter: got %+v", got)
	}
	if got := s.Recent(1, 1, "", "", "", ""); len(got) != 1 || got[0].SourceIP != "5.5.5.5" || got[0].RuleID != "xss-002" {
		t.Fatalf("offset skip: got %+v", got)
	}
}

func TestTopStrictSkipsEmpty(t *testing.T) {
	now := time.Now()
	evs := []events.Event{
		{Timestamp: now, Country: "TR", RuleID: "r1"},
		{Timestamp: now, Country: "TR", RuleID: "r1"},
		{Timestamp: now, RuleID: ""},
		{Timestamp: now, Country: "DE"},
	}
	countries := TopStrict(evs, func(e events.Event) string { return e.Country }, 10)
	if len(countries) != 2 || countries[0].Label != "TR" || countries[0].Count != 2 {
		t.Fatalf("countries mismatch: %+v", countries)
	}
	rules := TopStrict(evs, func(e events.Event) string { return e.RuleID }, 10)
	if len(rules) != 1 || rules[0].Label != "r1" || rules[0].Count != 2 {
		t.Fatalf("rules mismatch: %+v", rules)
	}
}

func TestSeriesCountsSoftActions(t *testing.T) {
	now := time.Now()
	evs := []events.Event{
		{Timestamp: now, Action: events.ActionRateLimit},
		{Timestamp: now.Add(time.Second), Action: events.ActionThrottle},
		{Timestamp: now.Add(2 * time.Second), Action: events.ActionUnauthorized},
	}
	pts := Series(evs, time.Minute, 15*time.Second, now.Add(30*time.Second))
	var rl, th, ua, total int
	for _, p := range pts {
		rl += p.RateLimited
		th += p.Throttled
		ua += p.Unauthorized
		total += p.Total
	}
	if rl != 1 || th != 1 || ua != 1 || total != 3 {
		t.Fatalf("series soft-action counts: rl=%d th=%d ua=%d total=%d", rl, th, ua, total)
	}
}
