package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const drainTimeout = 10 * time.Second

type Server struct {
	handler http.Handler
	cfg     *serverConfig
	log     *slog.Logger
}

type serverConfig struct {
	listenHTTPS string
	listenHTTP  string
	certFile    string
	keyFile     string
}

func NewServer(handler http.Handler, listenHTTPS, listenHTTP, certFile, keyFile string, log *slog.Logger) *Server {
	return &Server{
		handler: handler,
		cfg: &serverConfig{
			listenHTTPS: listenHTTPS,
			listenHTTP:  listenHTTP,
			certFile:    certFile,
			keyFile:     keyFile,
		},
		log: log,
	}
}

func (s *Server) Run(ctx context.Context) error {
	cert, err := tls.LoadX509KeyPair(s.cfg.certFile, s.cfg.keyFile)
	if err != nil {
		return fmt.Errorf("proxy: load TLS keypair (%s, %s): %w", s.cfg.certFile, s.cfg.keyFile, err)
	}
	httpsServer := &http.Server{
		Addr:    s.cfg.listenHTTPS,
		Handler: s.handler,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	servers := []*http.Server{httpsServer}
	errCh := make(chan error, 1)

	go func() {
		s.log.Info("openwaap edge listening", "addr", s.cfg.listenHTTPS, "tls", "true")
		errCh <- httpsServer.ListenAndServeTLS("", "")
	}()

	if s.cfg.listenHTTP != "" {
		httpMux := http.NewServeMux()
		httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			host := hostname(r.Host)
			target := "https://" + host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusPermanentRedirect)
		})
		httpServer := &http.Server{
			Addr:              s.cfg.listenHTTP,
			Handler:           httpMux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		servers = append(servers, httpServer)
		go func() {
			s.log.Info("openwaap http redirect listening", "addr", s.cfg.listenHTTP)
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.log.Error("http redirect listener failed; HTTPS edge continues without it",
					"addr", s.cfg.listenHTTP, "err", err)
			}
		}()
	}

	select {
	case runErr := <-errCh:
		s.drain(servers)
		return runErr
	case <-ctx.Done():
		s.log.Info("shutdown signal received, draining in-flight requests",
			"timeout", drainTimeout.String())
		s.drain(servers)
		return nil
	}
}

func (s *Server) drain(servers []*http.Server) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	done := make(chan struct{})
	for _, srv := range servers {
		go func(srv *http.Server) {
			if err := srv.Shutdown(shutdownCtx); err != nil && err != http.ErrServerClosed {
				s.log.Warn("graceful shutdown of listener failed", "addr", srv.Addr, "err", err)
			}
			done <- struct{}{}
		}(srv)
	}
	for i := 0; i < len(servers); i++ {
		<-done
	}
	s.log.Info("openwaap edge listeners drained")
}
