package testorigin

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
)

type Origin struct {
	ln        net.Listener
	srv       *http.Server
	requests  atomic.Int64
	blocked   atomic.Int64
	LastBlock atomic.Value
}

func New() (*Origin, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("testorigin: listen: %w", err)
	}
	o := &Origin{ln: ln}
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		o.requests.Add(1)
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><h1>Storefront</h1></body></html>"))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		o.requests.Add(1)
		if r.Body != nil {
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			o.LastBlock.Store(append([]byte(nil), buf[:n]...))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
			"csrf":   "token-abcdef",
		})
	})
	for _, p := range []string{"/products", "/api/search", "/blog"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			o.requests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"path": r.URL.Path})
		})
	}

	o.srv = &http.Server{Handler: mux}
	go func() { _ = o.srv.Serve(ln) }()
	return o, nil
}

func (o *Origin) Addr() string {
	return "http://" + o.ln.Addr().String()
}

func (o *Origin) ListenerAddr() string {
	return o.ln.Addr().String()
}

func (o *Origin) Requests() int64 { return o.requests.Load() }

func (o *Origin) Close() {
	_ = o.srv.Close()
	_ = o.ln.Close()
}
