package siem

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openwaap/openwaap/internal/events"
)

type batcher struct {
	name      string
	maxBuffer int
	batchSize int
	interval  time.Duration
	log       *slog.Logger
	deliver   func(ctx context.Context, batch []events.Event) error

	buf      chan events.Event
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	dropped  atomic.Uint64
	failed   atomic.Uint64
	sent     atomic.Uint64
}

func newBatcher(name string, maxBuffer, batchSize int, interval time.Duration, log *slog.Logger, deliver func(context.Context, []events.Event) error) *batcher {
	b := &batcher{
		name:      name,
		maxBuffer: maxBuffer,
		batchSize: batchSize,
		interval:  interval,
		log:       log,
		deliver:   deliver,
		buf:       make(chan events.Event, maxBuffer),
		stop:      make(chan struct{}),
	}
	b.Start()
	return b
}

func (b *batcher) Start() {
	b.wg.Add(1)
	go b.loop()
}

func (b *batcher) Emit(_ context.Context, ev events.Event) error {
	select {
	case b.buf <- ev:
		return nil
	default:
		b.dropped.Add(1)
		return nil
	}
}

func (b *batcher) loop() {
	defer b.wg.Done()
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	batch := make([]events.Event, 0, b.batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := b.deliver(context.Background(), batch); err != nil {
			b.failed.Add(uint64(len(batch)))
			b.log.Error("siem delivery failed", "sink", b.name, "err", err)
		} else {
			b.sent.Add(uint64(len(batch)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case ev, ok := <-b.buf:
			if !ok {
				flush()
				return
			}
			batch = append(batch, ev)
			if len(batch) >= b.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-b.stop:
			flush()
			return
		}
	}
}

func (b *batcher) Close() {
	b.stopOnce.Do(func() {
		close(b.stop)
	})
	b.wg.Wait()
}
