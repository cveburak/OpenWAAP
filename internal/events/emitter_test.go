package events

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type testCounter struct {
	n atomic.Uint64
}

func (c *testCounter) Incr(_ ...string) { c.n.Add(1) }

func (c *testCounter) get() uint64 { return c.n.Load() }

type failingSink struct{}

func (failingSink) Name() string                      { return "failing" }
func (failingSink) Emit(context.Context, Event) error { return errors.New("boom") }

func TestEmitterCountsDroppedEvents(t *testing.T) {
	e := NewEmitter(EmitterOptions{BufferSize: 2})
	defer e.Close()
	dc := &testCounter{}
	e.AttachMetrics(dc, nil)

	e.AddSink(slowSink{})
	for i := 0; i < 100; i++ {
		e.Emit(Event{})
	}
	deadline := time.Now().Add(2 * time.Second)
	for dc.get() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if dc.get() == 0 {
		t.Fatal("dropped-events counter was not incremented despite buffer overflow")
	}
}

func TestEmitterCountsSinkErrorsWhenClosed(t *testing.T) {
	e := NewEmitter(EmitterOptions{BufferSize: 8, FailOpen: false})
	defer e.Close()
	ec := &testCounter{}
	e.AttachMetrics(nil, ec)
	e.AddSink(failingSink{})

	e.Emit(Event{})
	deadline := time.Now().Add(2 * time.Second)
	for ec.get() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if ec.get() == 0 {
		t.Fatal("sink-error counter was not incremented")
	}
}

type slowSink struct{}

func (slowSink) Name() string { return "slow" }
func (slowSink) Emit(context.Context, Event) error {
	time.Sleep(20 * time.Millisecond)
	return nil
}
