package simulate

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type Case struct {
	Name   string
	Path   string
	Query  string
	Method string
	BlockedOK bool
	Body      string
}

func DefaultCases() []Case {
	return []Case{
		{Name: "benign homepage", Path: "/", Method: "GET"},
		{Name: "benign product listing", Path: "/products?id=5", Method: "GET"},
		{Name: "benign search", Path: "/api/search?q=shoes", Method: "GET"},
		{Name: "benign login form", Path: "/login", Method: "POST", Body: "username=alice&password=correcthorse"},

		{Name: "sqli union select", Path: "/products", Query: "id=1 UNION SELECT username FROM users", Method: "GET", BlockedOK: true},
		{Name: "sqli boolean", Path: "/products", Query: "id=1 OR 1=1", Method: "GET", BlockedOK: true},
		{Name: "sqli comment", Path: "/search", Query: "q=x' OR '1'='1' --", Method: "GET", BlockedOK: true},

		{Name: "xss script tag", Path: "/search", Query: "q=<script>alert(1)</script>", Method: "GET", BlockedOK: true},
		{Name: "xss img onerror", Path: "/blog", Query: "id=<img src=x onerror=alert(1)>", Method: "GET", BlockedOK: true},

		{Name: "rce command", Path: "/products", Query: "id=1;whoami", Method: "GET", BlockedOK: true},
		{Name: "rce substitution", Path: "/api/search", Query: "q=$(cat /etc/passwd)", Method: "GET", BlockedOK: true},

		{Name: "lfi etc/passwd", Path: "/products", Query: "file=../../../../etc/passwd", Method: "GET", BlockedOK: true},
		{Name: "path traversal", Path: "/products", Query: "file=../../app/config.php", Method: "GET", BlockedOK: true},

		{Name: "honeypot wp-admin", Path: "/wp-admin", Method: "GET", BlockedOK: true},
		{Name: "honeypot .env", Path: "/.env", Method: "GET", BlockedOK: true},

		{Name: "xss in body", Path: "/login", Method: "POST", Body: "email=<script>alert(1)</script>", BlockedOK: true},
	}
}

type Result struct {
	Case        Case
	StatusCode  int
	BodySnippet string
	ActuallyBlocked bool
	Passed bool
	Reason string
}

func Run(baseURL string, cases []Case, timeout time.Duration) []Result {
	return RunWithHost(baseURL, cases, timeout, "")
}

func RunWithHost(baseURL string, cases []Case, timeout time.Duration, host string) []Result {
	client := &http.Client{Timeout: timeout}
	if host != "" {
		client.Transport = &hostOverrideTransport{base: http.DefaultTransport, host: host}
	}
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results = make([]Result, 0, len(cases))
	)
	for _, c := range cases {
		wg.Add(1)
		go func(c Case) {
			defer wg.Done()
			res := runCase(client, baseURL, c)
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	sort.SliceStable(results, func(i, j int) bool { return results[i].Case.Name < results[j].Case.Name })
	return results
}

type hostOverrideTransport struct {
	base http.RoundTripper
	host string
}

func (t *hostOverrideTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	cp := r.Clone(r.Context())
	cp.Host = t.host
	if t.base == nil {
		return http.DefaultTransport.RoundTrip(cp)
	}
	return t.base.RoundTrip(cp)
}

func runCase(client *http.Client, baseURL string, c Case) Result {
	u, err := url.Parse(baseURL + c.Path)
	if err != nil {
		return Result{Case: c, Reason: "parse url: " + err.Error(), Passed: false}
	}
	if c.Query != "" {
		u.RawQuery = c.Query
		u.RawQuery = encodeRawQuery(c.Query)
	}
	method := c.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	var bodyStr string
	if c.Body != "" {
		body = strings.NewReader(c.Body)
		bodyStr = c.Body
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return Result{Case: c, Reason: "new request: " + err.Error(), Passed: false}
	}
	if c.Body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", "openwaap-test-simulator/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return Result{Case: c, Reason: "do: " + err.Error(), Passed: false}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	actualBlock := resp.StatusCode >= 400
	passed := actualBlock == c.BlockedOK
	reason := fmt.Sprintf("status=%d", resp.StatusCode)
	if len(bodyStr) > 0 && !passed {
		reason += " sentBody(truncated)=" + truncate(bodyStr, 40)
	}
	return Result{
		Case:            c,
		StatusCode:      resp.StatusCode,
		BodySnippet:     truncate(string(b), 120),
		ActuallyBlocked: actualBlock,
		Passed:          passed,
		Reason:          reason,
	}
}

func encodeRawQuery(q string) string {
	var sb strings.Builder
	for i := 0; i < len(q); i++ {
		ch := q[i]
		switch ch {
		case ' ':
			sb.WriteString("%20")
		case '"':
			sb.WriteString("%22")
		case '<':
			sb.WriteString("%3C")
		case '>':
			sb.WriteString("%3E")
		case '`':
			sb.WriteString("%60")
		default:
			sb.WriteByte(ch)
		}
	}
	return sb.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func Report(results []Result) string {
	var sb strings.Builder
	var pass, fail, blocked, allowed int
	for _, r := range results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		if r.Passed && r.ActuallyBlocked {
			blocked++
		} else if r.Passed {
			allowed++
		}
		if r.Passed {
			pass++
		} else {
			fail++
		}
		sb.WriteString(fmt.Sprintf("[%s] %-28s %s\n", status, r.Case.Name, r.Reason))
	}
	sb.WriteString(fmt.Sprintf("\n%d passed, %d failed (%d blocked, %d allowed)\n",
		pass, fail, blocked, allowed))
	return sb.String()
}
