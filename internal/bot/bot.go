package bot

import (
	"strings"
)

type Result struct {
	Score int
	Verified bool
	Label string
}

type Detector struct {
	verified []string
	evidence []Evidence
}

type Evidence struct {
	Pattern string
	Score   int
}

var DefaultVerifiedBots = []string{
	"googlebot", "bingbot", "duckduckbot", "baiduspider", "yandexbot",
	"applebot", "facebookexternalhit", "twitterbot", "slurp", "ahrefsbot",
	"semrushbot", "uptimerobot", "petalbot", "sogou",
}

var DefaultBotEvidence = []Evidence{
	{Pattern: "curl/", Score: 5},
	{Pattern: "wget", Score: 5},
	{Pattern: "python-requests", Score: 5},
	{Pattern: "python-urllib", Score: 6},
	{Pattern: "go-http-client", Score: 5},
	{Pattern: "node-fetch", Score: 10},
	{Pattern: "axios/", Score: 12},
	{Pattern: "okhttp", Score: 10},
	{Pattern: "scrapy", Score: 5},
	{Pattern: "headlesschrome", Score: 12},
	{Pattern: "phantomjs", Score: 10},
	{Pattern: "selenium", Score: 5},
	{Pattern: "postmanruntime", Score: 15},
	{Pattern: "libwww-perl", Score: 8},
	{Pattern: "java/", Score: 15},
	{Pattern: "httpie", Score: 12},
	{Pattern: "apache-httpclient", Score: 12},
	{Pattern: "bingpreview", Score: 40},
}

func New(verified []string, evidence []Evidence) *Detector {
	if len(verified) == 0 {
		verified = DefaultVerifiedBots
	}
	if len(evidence) == 0 {
		evidence = DefaultBotEvidence
	}
	return &Detector{verified: normalize(verified), evidence: evidence}
}

func normalize(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToLower(s)
	}
	return out
}

func (d *Detector) Scan(ua, accept, acceptLang string) Result {
	lower := strings.ToLower(strings.TrimSpace(ua))

	if lower == "" {
		return Result{Score: 8, Label: "no_user_agent"}
	}

	for _, v := range d.verified {
		if strings.Contains(lower, v) {
			return Result{Score: 80, Verified: true, Label: "verified_bot:" + v}
		}
	}

	best := Result{Score: 99, Label: "unknown"}
	matched := false
	for _, ev := range d.evidence {
		if strings.Contains(lower, ev.Pattern) {
			matched = true
			if ev.Score < best.Score {
				best = Result{Score: ev.Score, Label: "evidence:" + ev.Pattern}
			}
		}
	}
	if matched {
		return best
	}

	if strings.Contains(lower, "mozilla") || strings.Contains(lower, "chrome") ||
		strings.Contains(lower, "safari") || strings.Contains(lower, "edg") {
		if accept == "" || acceptLang == "" {
			return Result{Score: 40, Label: "partial_browser"}
		}
		return Result{Score: 75, Label: "browser"}
	}

	return Result{Score: 40, Label: "unknown"}
}
