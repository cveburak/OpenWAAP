package logging

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/events"
)

func testEvent(seq int) events.Event {
	return events.Event{
		Timestamp: time.Unix(int64(seq), 0),
		RequestID: "req",
		SourceIP:  "198.51.100.1",
		Hostname:  "example.com",
		Path:      "/",
		Method:    "GET",
		Action:    events.ActionAllow,
	}
}

func TestJSONLSinkRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	sink, err := NewJSONLSinkWithOptions(path, JSONLOptions{MaxBytes: 40, Keep: 2})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		if err := sink.Emit(context.Background(), testEvent(i)); err != nil {
			t.Fatal(err)
		}
	}

	archives, _ := filepath.Glob(path + ".*")
	if len(archives) != 2 {
		t.Errorf("expected exactly 2 archives (keep=2), got %d: %v", len(archives), archives)
	}

	data, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("archive .1 empty after rotation")
	}

	if err := sink.Emit(context.Background(), testEvent(99)); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestJSONLSinkNoRotationUnbounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	sink, err := NewJSONLSinkWithOptions(path, JSONLOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	for i := 0; i < 50; i++ {
		if err := sink.Emit(context.Background(), testEvent(i)); err != nil {
			t.Fatal(err)
		}
	}
	archives, _ := filepath.Glob(path + ".*")
	if len(archives) != 0 {
		t.Errorf("rotation disabled but %d archives found", len(archives))
	}
}

func TestForcedRotate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	sink, err := NewJSONLSinkWithOptions(path, JSONLOptions{Keep: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if err := sink.Emit(context.Background(), testEvent(1)); err != nil {
		t.Fatal(err)
	}
	if err := sink.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected %s.1 after forced rotate", path)
	}
	if err := sink.Emit(context.Background(), testEvent(2)); err != nil {
		t.Fatal(err)
	}
}
