package events

import (
	"context"
	"sync"
)

type Counter interface {
	Incr(labelValues ...string)
}

type Emitter struct {
	mu    sync.RWMutex
	sinks []Sink
	buf   chan Event
	once  sync.Once
	done  chan struct{}
	closed bool

	failOpen bool

	droppedC Counter
	errsC    Counter
}

type Sink interface {
	Name() string
	Emit(ctx context.Context, ev Event) error
}

type EmitterOptions struct {
	BufferSize int
	FailOpen bool
}

func NewEmitter(opts EmitterOptions) *Emitter {
	if opts.BufferSize <= 0 {
		opts.BufferSize = 4096
	}
	e := &Emitter{
		buf:      make(chan Event, opts.BufferSize),
		done:     make(chan struct{}),
		failOpen: opts.FailOpen,
	}
	go e.loop()
	return e
}

func (e *Emitter) AddSink(s Sink) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sinks = append(e.sinks, s)
}

func (e *Emitter) AttachMetrics(dropped, errs Counter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.droppedC = dropped
	e.errsC = errs
}

func (e *Emitter) Emit(ev Event) {
	e.mu.RLock()
	if e.closed {
		e.mu.RUnlock()
		return
	}
	dropped := false
	select {
	case e.buf <- ev:
	default:
		dropped = true
	}
	e.mu.RUnlock()
	if dropped {
		e.dropped()
	}
}

func (e *Emitter) Close() {
	e.once.Do(func() {
		e.mu.Lock()
		e.closed = true
		close(e.buf)
		e.mu.Unlock()
		<-e.done
	})
}

func (e *Emitter) loop() {
	defer close(e.done)
	for ev := range e.buf {
		e.dispatch(ev)
	}
}

func (e *Emitter) dispatch(ev Event) {
	e.mu.RLock()
	sinks := append([]Sink(nil), e.sinks...)
	errs := e.errsC
	e.mu.RUnlock()
	for _, s := range sinks {
		if err := s.Emit(context.Background(), ev); err != nil && !e.failOpen {
			if errs != nil {
				errs.Incr()
			}
		}
	}
}

func (e *Emitter) dropped() {
	e.mu.RLock()
	c := e.droppedC
	e.mu.RUnlock()
	if c != nil {
		c.Incr()
	}
}
