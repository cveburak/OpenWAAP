package behavior

import (
	"sync"
	"time"
)

type stat struct {
	firstSeen    time.Time
	lastSeen     time.Time
	requests     int
	ua           string
	consecGapCD  int
	bursts       int
	docSeen      bool
	assetDirect  int
	noCookie     int
	cookieIssued bool
	scripted     int
	uaChange     int
	revoked      bool
}

type Store struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	clients map[string]*stat
}

func NewStore(ttl time.Duration, max int) *Store {
	if max <= 0 {
		max = 10000
	}
	return &Store{ttl: ttl, max: max, clients: map[string]*stat{}}
}

const sweepBatch = 32

func (s *Store) touch(key string, now time.Time) *stat {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := now.Add(-s.ttl)
	scanned := 0
	for k, v := range s.clients {
		if v.lastSeen.Before(cut) {
			delete(s.clients, k)
		}
		scanned++
		if scanned >= sweepBatch {
			break
		}
	}
	if len(s.clients) >= s.max {
		evictOne(s.clients)
	}
	st, ok := s.clients[key]
	if !ok {
		st = &stat{firstSeen: now}
		s.clients[key] = st
	}
	st.lastSeen = now
	return st
}

func (s *Store) get(key string) *stat {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clients[key]
}

func (s *Store) adopt(ipKey, fpKey string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.clients[ipKey]
	if !ok {
		return false
	}
	delete(s.clients, ipKey)
	s.clients[fpKey] = st
	return true
}

func evictOne(m map[string]*stat) {
	for k := range m {
		delete(m, k)
		return
	}
}
