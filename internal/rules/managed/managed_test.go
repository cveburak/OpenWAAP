package managed

import (
	"strings"
	"testing"
)

func loadDefault(t *testing.T) *Ruleset {
	t.Helper()
	rs, err := LoadDefault()
	if err != nil {
		t.Fatalf("load default: %v", err)
	}
	return rs
}

func TestCompileBadRegex(t *testing.T) {
	data := `[{"id":"x","category":"SQL_INJECTION","field":"ARG_VALUE","pattern":"[unclosed","points":10,"enabled":true}]`
	if _, err := Compile("t", []byte(data)); err == nil {
		t.Fatal("expected error on bad regex")
	}
}

func TestCompileUnknownCategory(t *testing.T) {
	data := `[{"id":"x","category":"NOT_REAL","field":"ARG_VALUE","pattern":"abc","points":10,"enabled":true}]`
	if _, err := Compile("t", []byte(data)); err == nil {
		t.Fatal("expected error on unknown category")
	}
}

func TestUnionSelectDetection(t *testing.T) {
	rs := loadDefault(t)
	v := Values{
		URI:  "/products?id=1",
		Args: QueryStringArgs("id=1 UNION SELECT username,password FROM users"),
	}
	matches := rs.MatchAll(v, 1, 0)
	if len(matches) == 0 {
		t.Fatal("expected a match for UNION SELECT")
	}
	if matches[0].Rule.Category != CatSQLi {
		t.Fatalf("expected SQLi category, got %s", matches[0].Rule.Category)
	}
}

func TestPathTraversalDetection(t *testing.T) {
	rs := loadDefault(t)
	v := Values{
		URI:  "/file?name=../../../../etc/passwd",
		Args: QueryStringArgs("name=../../../../etc/passwd"),
	}
	matches := rs.MatchAll(v, 1, 0)
	if len(matches) == 0 {
		t.Fatal("expected a match for path traversal")
	}
}

func TestXSSDetection(t *testing.T) {
	rs := loadDefault(t)
	v := Values{
		URI:  "/search?q=<script>alert(1)</script>",
		Args: QueryStringArgs("q=<script>alert(1)</script>"),
	}
	matches := rs.MatchAll(v, 1, 0)
	if len(matches) == 0 {
		t.Fatal("expected a match for XSS")
	}
}

func TestLayeredShortCircuit(t *testing.T) {
	rs := loadDefault(t)
	v := Values{
		URI:  "/submit",
		Args: map[string]string{},
		Body: []byte(`{"user":"' OR 1=1 --"}`),
	}
	bodyCandidates := 0
	for _, r := range rs.Rules {
		if r.Field == FieldBody {
			bodyCandidates++
		}
	}
	_ = bodyCandidates
	matches := rs.MatchAll(v, 1, LayerURI)
	for _, m := range matches {
		if m.Rule.Layer > LayerURI {
			t.Fatalf("layer cap violated: matched rule in layer %d", m.Rule.Layer)
		}
	}
}

func TestParanoiaFilter(t *testing.T) {
	rs := loadDefault(t)
	v := Values{
		URI:  "/products?id=1 UNION SELECT 1",
		Args: QueryStringArgs("id=1 UNION SELECT 1"),
	}
	matches := rs.MatchAll(v, 0, 0)
	if len(matches) != 0 {
		t.Fatalf("expected no matches at paranoia 0, got %d", len(matches))
	}
}

func TestCategoryFilter(t *testing.T) {
	rs := loadDefault(t)
	active := map[string]bool{string(CatXSS): true}
	filtered := rs.FilterCategories(active)
	v := Values{
		URI:  "/search?q=<script>alert(1)</script>&id=1 UNION SELECT 1",
		Args: QueryStringArgs("q=<script>alert(1)</script>&id=1 UNION SELECT 1"),
	}
	matches := filtered.MatchAll(v, 2, 0)
	if len(matches) == 0 {
		t.Fatal("expected at least one XSS match")
	}
	for _, m := range matches {
		if m.Rule.Category != CatXSS {
			t.Fatalf("expected only XSS category, got %s", m.Rule.Category)
		}
	}
}

func TestQueryStringArgs(t *testing.T) {
	a := QueryStringArgs("a=1&b=2&a=3")
	if a["a"] != "1" || a["b"] != "2" {
		t.Fatalf("unexpected arg parse: %v", a)
	}
}

func TestDefaultHasAllCategories(t *testing.T) {
	rs := loadDefault(t)
	seen := map[Category]bool{}
	for _, r := range rs.Rules {
		seen[r.Category] = true
	}
	for _, c := range AllCategories {
		if !seen[c] {
			t.Fatalf("default ruleset missing category %s", c)
		}
	}
	if !strings.Contains(rs.String(), DefaultRulesetVersion) {
		t.Fatalf("expected version in String(), got %s", rs.String())
	}
}
