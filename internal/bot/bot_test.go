package bot

import (
	"strings"
	"testing"
)

func TestVerifiedBotsAllowed(t *testing.T) {
	d := New(nil, nil)
	for _, ua := range []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Twitterbot/1.0",
	} {
		r := d.Scan(ua, "*/*", "en")
		if !r.Verified {
			t.Errorf("UA %q should be verified, got %+v", ua, r)
		}
		if r.Score < 70 {
			t.Errorf("UA %q verified but score %d too low", ua, r.Score)
		}
	}
}

func TestBotEvidenceLowScore(t *testing.T) {
	d := New(nil, nil)
	cases := map[string]int{
		"curl/8.1.2 x86_64":               5,
		"python-requests/2.31.0":          5,
		"Wget/1.21.4":                     5,
		"Go-http-client/1.1":              5,
		"PostmanRuntime/7.26.8":           15,
		"HeadlessChrome/120.0.0.0":        12,
		"node-fetch/3.3":                  10,
		"Mozilla/5.0 X11; HeadlessChrome": 12,
	}
	for ua, want := range cases {
		r := d.Scan(ua, "*/*", "en")
		if r.Verified {
			t.Errorf("UA %q must not be verified", ua)
		}
		if r.Score > want+1 || r.Score < 1 {
			t.Errorf("UA %q: expected ~%d, got %d (%s)", ua, want, r.Score, r.Label)
		}
	}
}

func TestBrowserHighScore(t *testing.T) {
	d := New(nil, nil)
	r := d.Scan(
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"en-US,en;q=0.9",
	)
	if r.Verified || r.Score < 70 {
		t.Fatalf("expected human-like browser, got %+v", r)
	}
}

func TestPartialBrowser(t *testing.T) {
	d := New(nil, nil)
	ua := "Mozilla/5.0 (compatible; Googlebot-Unknown)"
	r := d.Scan(ua, "", "")
	if r.Verified {
		return
	}
	if r.Score > 45 {
		t.Fatalf("expected partial_browser suspicion, got %+v", r)
	}
}

func TestNoUA(t *testing.T) {
	d := New(nil, nil)
	r := d.Scan("", "", "")
	if r.Verified || r.Score > 10 {
		t.Fatalf("expected clear bot signal for empty UA, got %+v", r)
	}
}

func TestCustomVerifiedAndEvidence(t *testing.T) {
	d := New(
		[]string{"my-crawler"},
		[]Evidence{{Pattern: "evilbot/", Score: 3}},
	)
	if !d.Scan("my-crawler/1.0", "", "").Verified {
		t.Fatal("custom verified bot should be allowed")
	}
	if r := d.Scan("evilbot/2.0", "*/*", "*"); r.Score != 3 {
		t.Fatalf("custom evidence score expected 3, got %d", r.Score)
	}
}

func TestVerifiedSubstringPriority(t *testing.T) {
	d := New(nil, nil)
	ua := "Mozilla/5.0 (compatible; Googlebot/2.1; curl/8.1)"
	r := d.Scan(ua, "*/*", "en")
	if !r.Verified {
		t.Fatalf("verified priority failed: %+v", r)
	}
}

func TestUAnormalize(t *testing.T) {
	d := New(nil, nil)
	if !strings.Contains(d.verified[0], "googlebot") {
		t.Fatalf("normalized verified list missing googlebot: %v", d.verified[:2])
	}
}
