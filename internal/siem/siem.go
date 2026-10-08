package siem

import (
	"log/slog"
	"time"

	"github.com/openwaap/openwaap/internal/config"
	"github.com/openwaap/openwaap/internal/events"
)

func NewSinks(cfg *config.SIEMConfig, log *slog.Logger) ([]events.Sink, []func(), error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil, nil
	}
	if log == nil {
		log = slog.Default()
	}
	interval := cfg.BatchInterval.D()
	interval = coalesceDuration(interval, 2*time.Second)
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}
	maxBuffer := cfg.MaxBuffer
	if maxBuffer <= 0 {
		maxBuffer = 8192
	}

	var sinks []events.Sink
	var closers []func()
	for _, ep := range cfg.Endpoints {
		switch ep.Type {
		case "http":
			s, stop, err := newHTTPSink(ep, interval, batchSize, maxBuffer, log)
			if err != nil {
				closeAll(closers)
				return nil, nil, err
			}
			sinks = append(sinks, s)
			closers = append(closers, stop)
		case "syslog":
			s, stop, err := newSyslogSink(ep, interval, batchSize, maxBuffer, log)
			if err != nil {
				closeAll(closers)
				return nil, nil, err
			}
			sinks = append(sinks, s)
			closers = append(closers, stop)
		default:
			closeAll(closers)
			return nil, nil, &UnknownEndpointTypeError{Type: ep.Type}
		}
	}
	return sinks, closers, nil
}

type UnknownEndpointTypeError struct{ Type string }

func (e *UnknownEndpointTypeError) Error() string {
	return "siem: unsupported endpoint type " + e.Type
}

func coalesceDuration(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

func closeAll(closers []func()) {
	for i := len(closers) - 1; i >= 0; i-- {
		closers[i]()
	}
}
