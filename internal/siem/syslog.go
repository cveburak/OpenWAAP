package siem

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/openwaap/openwaap/internal/config"
	"github.com/openwaap/openwaap/internal/events"
)

const (
	priLocal0Info = 134
	hostnameCap   = 32
)

type syslogSink struct {
	batcher *batcher
	network string
	address string
	conn    net.Conn
	ts      func() time.Time
}

func newSyslogSink(ep config.SIEMEndpoint, interval time.Duration, batchSize, maxBuffer int, log *slog.Logger) (events.Sink, func(), error) {
	network := ep.Network
	if network == "" || network == "udp" {
		network = "udp"
	}
	if network != "udp" && network != "tcp" {
		return nil, nil, fmt.Errorf("siem syslog: network must be udp or tcp, got %q", ep.Network)
	}
	if ep.Address == "" {
		return nil, nil, fmt.Errorf("siem syslog: address is required")
	}
	s := &syslogSink{network: network, address: ep.Address, ts: time.Now}
	s.batcher = newBatcher("siem-syslog", maxBuffer, batchSize, interval, log, s.deliver)
	return s, s.Close, nil
}

func (s *syslogSink) Name() string { return "siem-syslog:" + s.network + ":" + s.address }

func (s *syslogSink) Emit(ctx context.Context, ev events.Event) error {
	return s.batcher.Emit(ctx, ev)
}

func (s *syslogSink) Close() { s.batcher.Close() }

func (s *syslogSink) deliver(_ context.Context, batch []events.Event) error {
	conn, err := s.connOrDial()
	if err != nil {
		return err
	}
	for i, ev := range batch {
		line := s.format(ev)
		if _, err := conn.Write([]byte(line)); err != nil {
			s.dropConn()
			return fmt.Errorf("syslog: %w", err)
		}
		_ = i
	}
	return nil
}

func (s *syslogSink) connOrDial() (net.Conn, error) {
	if s.conn != nil {
		return s.conn, nil
	}
	conn, err := net.DialTimeout(s.network, s.address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("syslog: dial %s %s: %w", s.network, s.address, err)
	}
	s.conn = conn
	return conn, nil
}

func (s *syslogSink) dropConn() {
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
}

func (s *syslogSink) format(ev events.Event) string {
	var b strings.Builder
	b.WriteString("<")
	b.WriteString(strconv.Itoa(priLocal0Info))
	b.WriteString(">")
	t := s.ts()
	b.WriteString(t.Format("Jan _2 15:04:05 "))
	host := ev.SourceIP
	if len(host) > hostnameCap {
		host = host[:hostnameCap]
	}
	b.WriteString(host)
	b.WriteString(" waap: ")
	b.WriteString(ev.RequestID)
	b.WriteString(" ")
	b.WriteString(strings.ToUpper(string(ev.Action)))
	b.WriteString("\n")
	return b.String()
}
