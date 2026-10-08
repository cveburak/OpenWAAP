package dashboard

import (
	"encoding/json"

	"github.com/openwaap/openwaap/internal/config"
	"github.com/openwaap/openwaap/internal/logging"
)

func cloneConfig(c *config.Config) (*config.Config, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	out := &config.Config{}
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, err
	}
	return out, nil
}

func redactConfig(c *config.Config) (*config.Config, error) {
	cp, err := cloneConfig(c)
	if err != nil {
		return nil, err
	}
	mask := func(s *string) {
		if *s != "" {
			*s = logging.MaskedValue
		}
	}
	mask(&cp.Security.HMACSecret)
	mask(&cp.Dashboard.AdminPassword)
	mask(&cp.Security.Store.Redis.Password)
	if cp.Security.SIEM != nil {
		for i := range cp.Security.SIEM.Endpoints {
			mask(&cp.Security.SIEM.Endpoints[i].Token)
			mask(&cp.Security.SIEM.Endpoints[i].HMACSecret)
		}
	}
	for i := range cp.Domains {
		d := &cp.Domains[i]
		if d.Behavior != nil {
			mask(&d.Behavior.Secret)
		}
		if d.APISecurity != nil && d.APISecurity.JWT != nil {
			mask(&d.APISecurity.JWT.Secret)
		}
	}
	return cp, nil
}
