package reputation

import (
	"math"
	"sync"
	"time"
)

type Store struct {
	mu  sync.Mutex
	m   map[string]*entry
	now func() time.Time
	DecayScorePerSecond float64
	PruneEvery int
	PruneIdle  time.Duration
	writes     int
}

type entry struct {
	score int
	seen  time.Time
}

func New(now func() time.Time) *Store {
	nt := time.Now
	if now != nil {
		nt = now
	}
	return &Store{
		m: map[string]*entry{}, now: nt, DecayScorePerSecond: 1.0 / 45.0,
		PruneEvery: 2048, PruneIdle: time.Hour,
	}
}

func (s *Store) Observe(ip string, points int) {
	if ip == "" || points <= 0 {
		return
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.m[ip]
	if e == nil {
		e = &entry{score: 0, seen: now}
		s.m[ip] = e
	}
	e.score = min100(e.score + points)
	e.seen = now

	if s.PruneEvery > 0 {
		s.writes++
		if s.writes >= s.PruneEvery {
			s.writes = 0
			s.pruneLocked(now, s.PruneIdle)
		}
	}
}

func (s *Store) Score(ip string) int {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.m[ip]
	if e == nil {
		return 0
	}
	e.score = s.decayed(e, now)
	e.seen = now
	return e.score
}

func (s *Store) decayed(e *entry, now time.Time) int {
	loss := int(math.Round(float64(now.Sub(e.seen).Seconds()) * s.DecayScorePerSecond))
	score := e.score - loss
	if score < 0 {
		score = 0
	}
	return score
}

func (s *Store) Prune(idle time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(s.now(), idle)
}

func (s *Store) pruneLocked(now time.Time, idle time.Duration) {
	for ip, e := range s.m {
		e.score = s.decayed(e, now)
		if e.score == 0 && now.Sub(e.seen) > idle {
			delete(s.m, ip)
		}
	}
}

func min100(v int) int {
	if v > 100 {
		return 100
	}
	return v
}
