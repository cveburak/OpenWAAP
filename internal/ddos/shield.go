package ddos

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/openwaap/openwaap/internal/config"
)

type Shield struct {
	cfg     config.DDoSConfig
	allow   []netip.Prefix
	now     func() time.Time
	mut     sync.Mutex
	perIP   map[string]*counter
	site    counter
	defense int64
	prunes  int
}

type counter struct {
	sec   int64
	count int64
	last  int64
}

func New(cfg config.DDoSConfig) (*Shield, error) {
	var prefixes []netip.Prefix
	for _, raw := range cfg.Allowlist {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			if addr, aerr := netip.ParseAddr(raw); aerr == nil {
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				p = netip.PrefixFrom(addr, bits)
			} else {
				return nil, fmt.Errorf("ddos: invalid allowlist %q: %w", raw, err)
			}
		}
		prefixes = append(prefixes, p.Masked())
	}
	return &Shield{
		cfg:   cfg,
		allow: prefixes,
		now:   time.Now,
		perIP: map[string]*counter{},
	}, nil
}

func (s *Shield) SetNow(fn func() time.Time) {
	s.mut.Lock()
	defer s.mut.Unlock()
	s.now = fn
}

func (s *Shield) Check(ip string) (config.Action, string) {
	if !s.cfg.Enabled || ip == "" {
		return config.ActionAllow, ""
	}
	if s.allowed(ip) {
		return config.ActionAllow, ""
	}
	s.mut.Lock()
	now := s.now()
	if len(s.perIP) > 65536 && s.prunes%128 == 0 {
		s.prune(now)
	}
	s.prunes++
	ipCount := s.hitIP(ip, now)
	siteCount := s.hitSite(now)
	if s.cfg.SiteBurstRPS > 0 && siteCount > int64(s.cfg.SiteBurstRPS) {
		ttl := s.cfg.DefenseTTL.D()
		if ttl <= 0 {
			ttl = 60 * time.Second
		}
		s.defense = now.Add(ttl).UnixNano()
	}
	defense := s.defense > 0 && now.UnixNano() < s.defense
	s.mut.Unlock()
	switch {
	case defense:
		return defenseAction(s.cfg), "ddos:defense"
	case s.cfg.PerIPRate > 0 && ipCount > int64(s.cfg.PerIPRate):
		return perIPAction(s.cfg), "ddos:per_ip"
	}
	return config.ActionAllow, ""
}

func (s *Shield) Active() bool {
	if !s.cfg.Enabled {
		return false
	}
	s.mut.Lock()
	defer s.mut.Unlock()
	return s.defense > 0 && s.now().UnixNano() < s.defense
}

func (s *Shield) allowed(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range s.allow {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Shield) hitIP(ip string, now time.Time) int64 {
	c := s.perIP[ip]
	if c == nil {
		s.perIP[ip] = &counter{sec: now.Unix(), count: 1, last: now.UnixNano()}
		return 1
	}
	c.last = now.UnixNano()
	if c.sec != now.Unix() {
		c.sec = now.Unix()
		c.count = 1
		return 1
	}
	c.count++
	return c.count
}

func (s *Shield) hitSite(now time.Time) int64 {
	if s.site.sec != now.Unix() {
		s.site.sec = now.Unix()
		s.site.count = 1
		return 1
	}
	s.site.count++
	return s.site.count
}

func (s *Shield) prune(now time.Time) {
	cutoff := now.Add(-10 * time.Second).UnixNano()
	for k, c := range s.perIP {
		if c.last < cutoff {
			delete(s.perIP, k)
		}
	}
}

func defenseAction(cfg config.DDoSConfig) config.Action {
	if cfg.DefenseAction == "block" {
		return config.ActionBlock
	}
	return config.ActionChallenge
}

func perIPAction(cfg config.DDoSConfig) config.Action {
	if cfg.PerIPAction == "block" {
		return config.ActionBlock
	}
	return config.ActionChallenge
}
