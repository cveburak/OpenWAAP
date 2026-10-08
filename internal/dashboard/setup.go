package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/openwaap/openwaap/internal/config"
	"github.com/openwaap/openwaap/internal/selfsigned"
)

type setupAPIRequest struct {
	Config *config.Config `json:"config"`
	GenerateCert bool `json:"generate_cert"`
	Hosts []string `json:"hosts"`
}

func (h *Handler) handleSetup(w http.ResponseWriter, r *http.Request) {
	if h.panel == nil {
		http.NotFound(w, r)
		return
	}
	var in setupAPIRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid setup payload: " + err.Error()})
		return
	}
	if in.Config == nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing config document"})
		return
	}
	nc := *in.Config
	nc.SetupPending = false

	if err := validateAdminPasswordStrength(nc.Dashboard.AdminUser, nc.Dashboard.AdminPassword, nc.Domains); err != nil {
		h.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	if err := nc.NormalizeAdminPassword(); err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot hash admin password"})
		return
	}

	if in.GenerateCert {
		if nc.Server.TLSCertFile == "" || nc.Server.TLSKeyFile == "" {
			nc.Server.TLSCertFile = filepath.Join(defaultCertDir(h.cfgPath), "edge.pem")
			nc.Server.TLSKeyFile = filepath.Join(defaultCertDir(h.cfgPath), "edge.key")
		}
		if err := selfsigned.Generate(nc.Server.TLSCertFile, nc.Server.TLSKeyFile, in.Hosts); err != nil {
			h.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
	} else if nc.Server.TLSCertFile != "" || nc.Server.TLSKeyFile != "" {
		if !selfsigned.Exists(nc.Server.TLSCertFile, nc.Server.TLSKeyFile) {
			h.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
				"error": "TLS certificate/key files configured by server.tls_cert_file/tls_key_file do not exist",
			})
			return
		}
	}

	if err := nc.Validate(); err != nil {
		h.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}

	if _, err := h.panel.Apply(&nc); err != nil {
		h.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "persist: " + err.Error()})
		return
	}
	if err := h.panel.Restart(); err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "restart: " + err.Error()})
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restart": true, "to": "/-/login"})
}

const minAdminPasswordLen = 12

func validateAdminPasswordStrength(username, password string, domains []config.DomainConfig) error {
	if password == "" {
		return nil
	}
	if len(password) < minAdminPasswordLen {
		return fmt.Errorf("admin password must be at least %d characters", minAdminPasswordLen)
	}
	lp := strings.ToLower(password)
	if u := strings.ToLower(strings.TrimSpace(username)); u != "" && strings.Contains(lp, u) {
		return fmt.Errorf("admin password must not contain the admin username")
	}
	for _, d := range domains {
		if h := strings.ToLower(strings.TrimSpace(d.Hostname)); h != "" && strings.Contains(lp, h) {
			return fmt.Errorf("admin password must not contain the protected hostname")
		}
	}
	return nil
}

func defaultCertDir(cfgPath string) string {
	return selfsigned.DefaultDir(cfgPath)
}
