package ddos

import (
	"testing"
	"time"

	"github.com/openwaap/openwaap/internal/config"
)

func tNow(t *testing.T, s *Shield, t0 time.Time) func(time.Duration) {
	t.Helper()
	n := t0
	s.SetNow(func() time.Time { return n })
	return func(d time.Duration) { n = n.Add(d) }
}

func TestDisabled(t *testing.T) {
	s, err := New(config.DDoSConfig{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	act, _ := s.Check("1.2.3.4")
	if act != config.ActionAllow {
		t.Fatal(act)
	}
}

func TestAllowlist(t *testing.T) {
	s, err := New(config.DDoSConfig{Enabled: true, PerIPRate: 1, PerIPAction: "challenge", Allowlist: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	tNow(t, s, time.Now())
	act, _ := s.Check("10.0.0.1")
	if act != config.ActionAllow {
		t.Fatal("allowlisted")
	}
	act, _ = s.Check("10.0.0.2")
	if act != config.ActionAllow {
		t.Fatal("allowlisted 2")
	}
}

func TestPerIPBlock(t *testing.T) {
	s, err := New(config.DDoSConfig{Enabled: true, PerIPRate: 2, PerIPAction: "block"})
	if err != nil {
		t.Fatal(err)
	}
	adv := tNow(t, s, time.Now())
	for i := 0; i < 2; i++ {
		act, rule := s.Check("1.1.1.1")
		if act != config.ActionAllow {
			t.Fatalf("req %d: expected allow got %s %s", i, act, rule)
		}
	}
	act, rule := s.Check("1.1.1.1")
	if act != config.ActionBlock || rule != "ddos:per_ip" {
		t.Fatalf("expected block per_ip, got %s %s", act, rule)
	}
	adv(time.Second)
	act, _ = s.Check("1.1.1.1")
	if act != config.ActionAllow {
		t.Fatalf("expected allow after window reset, got %s", act)
	}
}

func TestPerIPChallenge(t *testing.T) {
	s, err := New(config.DDoSConfig{Enabled: true, PerIPRate: 3})
	if err != nil {
		t.Fatal(err)
	}
	tNow(t, s, time.Now())
	for i := 0; i < 3; i++ {
		s.Check("2.2.2.2")
	}
	act, rule := s.Check("2.2.2.2")
	if act != config.ActionChallenge || rule != "ddos:per_ip" {
		t.Fatalf("expected challenge per_ip, got %s %s", act, rule)
	}
}

func TestDefenseMode(t *testing.T) {
	s, err := New(config.DDoSConfig{
		Enabled:       true,
		SiteBurstRPS:  5,
		DefenseAction: "challenge",
		DefenseTTL:    config.Duration(2 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	adv := tNow(t, s, time.Now())
	for i := 0; i < 6; i++ {
		s.Check("9.9.9.9")
	}
	if !s.Active() {
		t.Fatal("defense should be active after site burst")
	}
	act, rule := s.Check("8.8.8.8")
	if act != config.ActionChallenge || rule != "ddos:defense" {
		t.Fatalf("expected challenge defense, got %s %s", act, rule)
	}
	adv(3 * time.Second)
	if s.Active() {
		t.Fatal("defense should have expired")
	}
	act, _ = s.Check("8.8.8.8")
	if act != config.ActionAllow {
		t.Fatalf("expected allow after defense expired, got %s", act)
	}
}

func TestDefenseBlock(t *testing.T) {
	s, err := New(config.DDoSConfig{
		Enabled:       true,
		SiteBurstRPS:  2,
		DefenseAction: "block",
		DefenseTTL:    config.Duration(1 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	adv := tNow(t, s, time.Now())
	for i := 0; i < 3; i++ {
		s.Check("5.5.5.5")
	}
	act, _ := s.Check("5.5.5.5")
	if act != config.ActionBlock {
		t.Fatalf("expected block defense, got %s", act)
	}
	adv(2 * time.Second)
	act, _ = s.Check("5.5.5.5")
	if act != config.ActionAllow {
		t.Fatalf("expected allow after defense expired, got %s", act)
	}
}

func TestMixedPerIPandDefense(t *testing.T) {
	s, err := New(config.DDoSConfig{
		Enabled:       true,
		PerIPRate:     1,
		PerIPAction:   "block",
		SiteBurstRPS:  4,
		DefenseAction: "challenge",
		DefenseTTL:    config.Duration(1 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	adv := tNow(t, s, time.Now())
	for i := 0; i < 5; i++ {
		s.Check("1.2.3.4")
	}
	act, rule := s.Check("9.9.9.9")
	if act != config.ActionChallenge || rule != "ddos:defense" {
		t.Fatalf("expected defense challenge, got %s %s", act, rule)
	}
	_ = adv
}

func TestPrune(t *testing.T) {
	s, err := New(config.DDoSConfig{Enabled: true, PerIPRate: 1})
	if err != nil {
		t.Fatal(err)
	}
	adv := tNow(t, s, time.Now())
	for i := 0; i < 200000; i++ {
		ip := "10." + itoa(i>>16%256) + "." + itoa(i>>8%256) + "." + itoa(i%256)
		s.Check(ip)
	}
	s.mut.Lock()
	if n := len(s.perIP); n < 199990 {
		t.Fatalf("expected ~200k tracked IPs, got %d", n)
	}
	s.mut.Unlock()
	adv(30 * time.Second)
	s.prune(s.now())
	s.mut.Lock()
	defer s.mut.Unlock()
	if n := len(s.perIP); n != 0 {
		t.Fatalf("expected all stale IPs pruned, got %d", n)
	}
}

func itoa(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

func TestEmptyIP(t *testing.T) {
	s, err := New(config.DDoSConfig{Enabled: true, PerIPRate: 0})
	if err != nil {
		t.Fatal(err)
	}
	s.SetNow(func() time.Time { return time.Now() })
	act, _ := s.Check("")
	if act != config.ActionAllow {
		t.Fatal("empty IP should allow")
	}
}
