package siem

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/config"
	"github.com/openwaap/openwaap/internal/events"
)

func testEvent(id, action string) events.Event {
	return events.Event{RequestID: id, SourceIP: "203.0.113.9", Action: events.Action(action), Path: "/x"}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestHTTPSinkBatch(t *testing.T) {
	var (
		mu  sync.Mutex
		got [][]byte
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		got = append(got, body)
		if r.Header.Get("Authorization") != "Bearer tok123" {
			t.Errorf("missing bearer token")
		}
		mac := hmac.New(sha256.New, []byte("sekret"))
		mac.Write(body)
		if r.Header.Get("X-WAAP-Signature") != hex.EncodeToString(mac.Sum(nil)) {
			t.Errorf("bad signature")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, stop, err := newHTTPSink(config.SIEMEndpoint{URL: server.URL, Token: "tok123", HMACSecret: "sekret"}, 30*time.Millisecond, 2, 64, slog.New(slog.NewTextHandler(ioutil.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	for i := 0; i < 3; i++ {
		_ = sink.Emit(nil, testEvent(fmt.Sprintf("req-%d", i), "block"))
	}

	waitFor(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) >= 2
	})

	mu.Lock()
	defer mu.Unlock()
	total := 0
	for _, body := range got {
		var batch []events.Event
		if err := json.Unmarshal(body, &batch); err != nil {
			t.Fatalf("batch not json array: %v", err)
		}
		total += len(batch)
		if len(batch) > 2 {
			t.Fatalf("batch larger than configured size: %d", len(batch))
		}
	}
	if total != 3 {
		t.Fatalf("lost events: got %d of 3", total)
	}
}

func TestSyslogSinkUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().String()

	sink, stop, err := newSyslogSink(config.SIEMEndpoint{Network: "udp", Address: addr}, 30*time.Millisecond, 5, 64, slog.New(slog.NewTextHandler(ioutil.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	_ = sink.Emit(nil, testEvent("abc", "challenge"))
	_ = sink.Emit(nil, testEvent("def", "block"))

	buf := make([]byte, 4096)
	saw := map[string]bool{}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		line := string(buf[:n])
		if len(line) == 0 || line[0] != '<' {
			t.Fatalf("missing PRI: %q", line)
		}
		for _, rid := range []string{"abc", "def"} {
			if contains(line, rid) {
				saw[rid] = true
			}
		}
		if len(saw) == 2 {
			break
		}
	}
	if len(saw) != 2 {
		t.Fatalf("syslog lines missing, got %v", saw)
	}
}

func TestUnknownEndpointType(t *testing.T) {
	cfg := &config.SIEMConfig{Enabled: true, Endpoints: []config.SIEMEndpoint{{Type: "kafka"}}}
	if _, _, err := NewSinks(cfg, nil); err == nil {
		t.Fatal("expected error for unknown endpoint type")
	}
}

func TestDisabledConfigNoSinks(t *testing.T) {
	if sinks, closers, err := NewSinks(nil, nil); err != nil || sinks != nil || closers != nil {
		t.Fatalf("nil config must return nothing: %v %v %v", sinks, closers, err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
