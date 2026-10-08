package logging

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/openwaap/openwaap/internal/events"
)

type JSONLSink struct {
	mu sync.Mutex
	w  *bufio.Writer
	f  *os.File

	path     string
	written  int64
	maxBytes int64
	keep     int
}

type JSONLOptions struct {
	MaxBytes int64
	Keep int
}

func NewJSONLSink(path string) (*JSONLSink, error) {
	return NewJSONLSinkWithOptions(path, JSONLOptions{})
}

func NewJSONLSinkWithOptions(path string, opts JSONLOptions) (*JSONLSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("logging: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("logging: open %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("logging: stat %s: %w", path, err)
	}
	keep := opts.Keep
	if keep < 0 {
		keep = 0
	}
	return &JSONLSink{
		w:        bufio.NewWriter(f),
		f:        f,
		path:     path,
		written:  info.Size(),
		maxBytes: opts.MaxBytes,
		keep:     keep,
	}, nil
}

func (s *JSONLSink) Name() string { return "jsonl:" + s.path }

func (s *JSONLSink) Emit(ctx context.Context, ev events.Event) error {
	data, err := ev.ToJSON()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(data); err != nil {
		return err
	}
	if err := s.w.WriteByte('\n'); err != nil {
		return err
	}
	if err := s.w.Flush(); err != nil {
		return err
	}
	s.written += int64(len(data) + 1)
	if s.maxBytes > 0 && s.written >= s.maxBytes {
		return s.rotateLocked()
	}
	return nil
}

func (s *JSONLSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.w.Flush(); err != nil {
		return err
	}
	return s.f.Close()
}

func (s *JSONLSink) FilePath() string { return s.path }

func (s *JSONLSink) Rotate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.w.Flush(); err != nil {
		return err
	}
	return s.rotateLocked()
}

func (s *JSONLSink) rotateLocked() error {
	if err := s.w.Flush(); err != nil {
		return err
	}
	if err := s.f.Close(); err != nil {
		return err
	}

	if s.keep > 0 {
		oldest := s.keep
		if s.keep > 1 {
			prunePath := fmt.Sprintf("%s.%d", s.path, oldest)
			_ = os.Remove(prunePath)
			for n := s.keep - 1; n >= 1; n-- {
				src := fmt.Sprintf("%s.%d", s.path, n)
				dst := fmt.Sprintf("%s.%d", s.path, n+1)
				_ = os.Rename(src, dst)
			}
		}
		if err := os.Rename(s.path, fmt.Sprintf("%s.1", s.path)); err != nil {
			return fmt.Errorf("logging: rotate rename: %w", err)
		}
	}

	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("logging: reopen %s: %w", s.path, err)
	}
	s.w = bufio.NewWriter(f)
	s.f = f
	s.written = 0
	return nil
}

var _ events.Sink = (*JSONLSink)(nil)

var TimeNow = time.Now
