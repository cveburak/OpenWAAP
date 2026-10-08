package dashboard

import "github.com/openwaap/openwaap/internal/config"

type PanelController interface {
	Config() *config.Config

	Apply(cfg *config.Config) (restartRequired []string, err error)

	Restart() error
}
