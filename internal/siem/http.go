package siem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/openwaap/openwaap/internal/config"
	"github.com/openwaap/openwaap/internal/events"
)

const clientTimeout = 10 * time.Second

type httpSink struct {
	batcher  *batcher
	endpoint string
	token    string
	hmacKey  []byte
	client   *http.Client
}

func newHTTPSink(ep config.SIEMEndpoint, interval time.Duration, batchSize, maxBuffer int, log *slog.Logger) (events.Sink, func(), error) {
	if _, err := url.ParseRequestURI(ep.URL); err != nil {
		return nil, nil, fmt.Errorf("siem http: invalid url %q: %w", ep.URL, err)
	}
	s := &httpSink{
		endpoint: ep.URL,
		token:    ep.Token,
		hmacKey:  []byte(ep.HMACSecret),
		client:   &http.Client{Timeout: clientTimeout},
	}
	s.batcher = newBatcher("siem-http", maxBuffer, batchSize, interval, log, s.deliver)
	return s, s.Close, nil
}

func (s *httpSink) Name() string { return "siem-http:" + s.endpoint }

func (s *httpSink) Emit(ctx context.Context, ev events.Event) error {
	return s.batcher.Emit(ctx, ev)
}

func (s *httpSink) Close() { s.batcher.Close() }

func (s *httpSink) deliver(_ context.Context, batch []events.Event) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("siem http: marshal: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("siem http: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	if len(s.hmacKey) > 0 {
		mac := hmac.New(sha256.New, s.hmacKey)
		mac.Write(body)
		req.Header.Set("X-WAAP-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("siem http: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("siem http: collector returned %d", resp.StatusCode)
	}
	return nil
}

var _ events.Sink = (*httpSink)(nil)
