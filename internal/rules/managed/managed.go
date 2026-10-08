package managed

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type Category string

const (
	CatSQLi          Category = "SQL_INJECTION"
	CatXSS           Category = "XSS"
	CatRCE           Category = "RCE"
	CatLFI           Category = "LFI"
	CatPathTraversal Category = "PATH_TRAVERSAL"
)

var AllCategories = []Category{CatSQLi, CatXSS, CatRCE, CatLFI, CatPathTraversal}

type Field string

const (
	FieldArgName  Field = "ARG_NAME"
	FieldArgValue Field = "ARG_VALUE"
	FieldURI      Field = "URI"
	FieldHeader   Field = "HEADER"
	FieldBody     Field = "BODY"
)

type Layer int

const (
	LayerURI      Layer = 1
	LayerHeader   Layer = 2
	LayerBody     Layer = 3
	LayerBehavior Layer = 4
)

type Rule struct {
	ID          string   `json:"id"`
	Category    Category `json:"category"`
	Description string   `json:"description"`
	Field       Field    `json:"field"`
	Layer   Layer  `json:"-"`
	Pattern string `json:"pattern"`
	re      *regexp.Regexp
	Points     int      `json:"points"`
	Paranoia   int      `json:"paranoia"`
	Enabled    bool     `json:"enabled"`
	TargetArgs []string `json:"target_args,omitempty"`
}

type Match struct {
	Rule Rule
	Detail string
}

type Ruleset struct {
	Version string
	Rules   []Rule
}

type rawRule struct {
	ID          string   `json:"id" yaml:"id"`
	Category    Category `json:"category" yaml:"category"`
	Description string   `json:"description" yaml:"description"`
	Field       Field    `json:"field" yaml:"field"`
	Pattern     string   `json:"pattern" yaml:"pattern"`
	Points      int      `json:"points" yaml:"points"`
	Paranoia    int      `json:"paranoia" yaml:"paranoia"`
	Enabled     bool     `json:"enabled" yaml:"enabled"`
	TargetArgs  []string `json:"target_args,omitempty" yaml:"target_args,omitempty"`
}

func layerForField(f Field) Layer {
	switch f {
	case FieldURI, FieldArgName, FieldArgValue:
		return LayerURI
	case FieldHeader:
		return LayerHeader
	case FieldBody:
		return LayerBody
	}
	return LayerURI
}

func Compile(version string, data []byte) (*Ruleset, error) {
	var raws []rawRule
	if err := json.Unmarshal(data, &raws); err != nil {
		return nil, fmt.Errorf("managed: parse ruleset: %w", err)
	}
	rs := &Ruleset{Version: version, Rules: make([]Rule, 0, len(raws))}
	ids := map[string]bool{}
	for _, r := range raws {
		if r.ID == "" {
			return nil, fmt.Errorf("managed: rule missing id")
		}
		if ids[r.ID] {
			return nil, fmt.Errorf("managed: duplicate rule id %q", r.ID)
		}
		ids[r.ID] = true
		if _, ok := validCategories[r.Category]; !ok {
			return nil, fmt.Errorf("managed: rule %q unknown category %q", r.ID, r.Category)
		}
		if _, ok := validFields[r.Field]; !ok {
			return nil, fmt.Errorf("managed: rule %q unknown field %q", r.ID, r.Field)
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("managed: rule %q bad pattern: %w", r.ID, err)
		}
		rs.Rules = append(rs.Rules, Rule{
			ID:          r.ID,
			Category:    r.Category,
			Description: r.Description,
			Field:       r.Field,
			Layer:       layerForField(r.Field),
			Pattern:     r.Pattern,
			re:          re,
			Points:      r.Points,
			Paranoia:    r.Paranoia,
			Enabled:     r.Enabled,
			TargetArgs:  r.TargetArgs,
		})
	}
	sort.SliceStable(rs.Rules, func(i, j int) bool { return rs.Rules[i].Layer < rs.Rules[j].Layer })
	return rs, nil
}

var (
	validCategories = map[Category]bool{CatSQLi: true, CatXSS: true, CatRCE: true, CatLFI: true, CatPathTraversal: true}
	validFields     = map[Field]bool{FieldArgName: true, FieldArgValue: true, FieldURI: true, FieldHeader: true, FieldBody: true}
)

func (rs *Ruleset) MatchAll(values Values, maxParanoia int, layerCap Layer) []Match {
	if rs == nil {
		return nil
	}
	var out []Match
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if !r.Enabled || r.Paranoia > maxParanoia {
			continue
		}
		if layerCap > 0 && r.Layer > layerCap {
			continue
		}
		if m, ok := r.match(values); ok {
			out = append(out, m)
		}
	}
	return out
}

func (r *Rule) match(values Values) (Match, bool) {
	var detail string
	switch r.Field {
	case FieldURI:
		if r.re.MatchString(values.URI) {
			detail = "uri:" + truncate(values.URI, 120)
			return r.result(detail), true
		}
	case FieldArgName:
		for name := range values.Args {
			if r.re.MatchString(name) {
				detail = "arg_name:" + truncate(name, 80)
				return r.result(detail), true
			}
		}
	case FieldArgValue:
		for name, val := range values.Args {
			if len(r.TargetArgs) > 0 && !containsStr(r.TargetArgs, name) {
				continue
			}
			if r.re.MatchString(val) {
				detail = "arg_value(" + name + "):" + truncate(val, 120)
				return r.result(detail), true
			}
		}
	case FieldHeader:
		for hname, vals := range values.Headers {
			for _, v := range vals {
				if r.re.MatchString(v) {
					detail = "header(" + hname + "):" + truncate(v, 120)
					return r.result(detail), true
				}
			}
		}
	case FieldBody:
		if r.re.Match(values.Body) {
			detail = "body:" + truncate(string(values.Body), 120)
			return r.result(detail), true
		}
	}
	return Match{}, false
}

func (r *Rule) result(detail string) Match {
	return Match{Rule: *r, Detail: detail}
}

type Values struct {
	URI     string
	Args    map[string]string
	Headers map[string][]string
	Body    []byte
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func QueryStringArgs(rawQuery string) map[string]string {
	args := map[string]string{}
	for _, kv := range strings.Split(rawQuery, "&") {
		if kv == "" {
			continue
		}
		parts := strings.SplitN(kv, "=", 2)
		name := parts[0]
		if _, seen := args[name]; seen {
			continue
		}
		if len(parts) == 2 {
			args[name] = parts[1]
		} else {
			args[name] = ""
		}
	}
	return args
}
