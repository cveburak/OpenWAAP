package events

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	reqctx "github.com/openwaap/openwaap/internal/context"
)

type captureSink struct {
	mu     sync.Mutex
	events []Event
}

func (c *captureSink) Name() string { return "capture" }
func (c *captureSink) Emit(_ context.Context, ev Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return nil
}

func TestFromContext(t *testing.T) {
	c := &reqctx.RequestContext{
		Timestamp:   time.Now(),
		RequestID:   "r-1",
		RemoteIP:    net.ParseIP("203.0.113.5"),
		Host:        "example.com",
		Path:        "/login",
		Method:      "POST",
		AttackScore: 85,
		BotScore:    30,
		HoneypotHit: false,
	}
	c.AddSignal(reqctx.SignalMatch{Source: "waf", RuleID: "sqli-1", Category: "SQL_INJECTION", Points: 60})
	ev := FromContext(c, "BLOCK", "sqli-1")
	if ev.Action != "BLOCK" {
		t.Fatalf("expected BLOCK, got %s", ev.Action)
	}
	if ev.Category != "SQL_INJECTION" {
		t.Fatalf("expected SQL_INJECTION, got %s", ev.Category)
	}
	if ev.AttackScore != 85 {
		t.Fatalf("expected score 85, got %d", ev.AttackScore)
	}
	if ev.MatchCount != 1 {
		t.Fatalf("expected 1 match, got %d", ev.MatchCount)
	}
	if ev.SourceIP != "203.0.113.5" {
		t.Fatalf("expected source ip, got %s", ev.SourceIP)
	}
	if b, err := ev.ToJSON(); err != nil || b == nil {
		t.Fatal("expected JSON output")
	}
}

func TestEmitterDeliveryAndClose(t *testing.T) {
	s := &captureSink{}
	e := NewEmitter(EmitterOptions{BufferSize: 64})
	e.AddSink(s)
	ev := Event{RequestID: "r1", Action: "BLOCK"}
	e.Emit(ev)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := len(s.events)
		s.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event delivered, got %d", len(s.events))
	}
	if s.events[0].RequestID != "r1" {
		t.Fatalf("unexpected event: %+v", s.events[0])
	}
	e.Close()
}
