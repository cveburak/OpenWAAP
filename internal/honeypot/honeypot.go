package honeypot

import (
	"fmt"
	"sort"
	"strings"
)

const DefaultPoints = 99

var defaultDecoys = []string{
	"/wp-admin",
	"/wp-login.php",
	"/.env",
	"/.git/config",
	"/admin/config.php",
	"/phpmyadmin",
	"/server-status",
	"/config.php.bak",
	"/backup.zip",
	"/.dockerenv",
	"/actuator/env",
	"/elb-tmp",
}

type Registry struct {
	decoys map[string]struct{}
	points int
}

func NewRegistry(configured []string, autoGenerate bool, points int) *Registry {
	if points <= 0 {
		points = DefaultPoints
	}
	r := &Registry{decoys: map[string]struct{}{}, points: points}
	for _, p := range configured {
		if p != "" {
			r.decoys[normalize(p)] = struct{}{}
		}
	}
	if autoGenerate {
		for _, p := range defaultDecoys {
			r.decoys[normalize(p)] = struct{}{}
		}
	}
	return r
}

func (r *Registry) IsDecoy(path string) bool {
	if r == nil {
		return false
	}
	_, ok := r.decoys[normalize(path)]
	return ok
}

func (r *Registry) Points() int {
	if r == nil {
		return DefaultPoints
	}
	return r.points
}

func (r *Registry) Paths() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.decoys))
	for p := range r.decoys {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func Explain(path string) string {
	return fmt.Sprintf("Honeypot decoy endpoint hit: %s (no legitimate client visits this path)", path)
}

func normalize(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}
