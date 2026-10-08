package managed

import (
	_ "embed"
	"fmt"
)

const DefaultRulesetVersion = "1.0.0"

//go:embed default_rules.json
var defaultRulesJSON []byte

func LoadDefault() (*Ruleset, error) {
	return Compile(DefaultRulesetVersion, defaultRulesJSON)
}

func (rs *Ruleset) FilterCategories(active map[string]bool) *Ruleset {
	if rs == nil {
		return &Ruleset{}
	}
	out := &Ruleset{Version: rs.Version}
	for _, r := range rs.Rules {
		enabled := active[string(r.Category)]
		enabled = enabled && r.Enabled
		out.Rules = append(out.Rules, r)
		out.Rules[len(out.Rules)-1].Enabled = enabled
	}
	return out
}

func (rs *Ruleset) String() string {
	if rs == nil {
		return "Ruleset{nil}"
	}
	return fmt.Sprintf("Ruleset{version=%s, rules=%d}", rs.Version, len(rs.Rules))
}
