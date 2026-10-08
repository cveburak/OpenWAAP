package proxy

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/selfsigned"
)

func TestHTTPRedirectListenerBindFailureDoesNotKillHTTPS(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "edge.pem")
	keyPath := filepath.Join(dir, "edge.key")
	if err := selfsigned.Generate(certPath, keyPath, []string{"localhost"}); err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	defer blocker.Close()
	httpAddr := blocker.Addr().String()

	httpsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve https port: %v", err)
	}
	httpsAddr := httpsLn.Addr().String()
	httpsLn.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := NewServer(handler, httpsAddr, httpAddr, certPath, keyPath, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()

	time.Sleep(200 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   2 * time.Second,
	}
	resp, err := client.Get("https://" + httpsAddr + "/")
	if err != nil {
		t.Fatalf("HTTPS edge not reachable after HTTP listener bind conflict: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status from HTTPS edge: %d", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned an error on clean shutdown: %v", err)
		}
	case <-time.After(drainTimeout + 2*time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}
