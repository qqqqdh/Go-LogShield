package llm

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"go-logshield/internal/normalizer"
)

// SessionContext holds isolated behavior history for an IP|Service correlation key.
type SessionContext struct {
	IP         string
	Service    string
	Epoch      int
	CreatedAt  time.Time
	LastSeenAt time.Time
	Events     []normalizer.Event
}

func NewSessionContext(ip string, service string, now time.Time) *SessionContext {
	if service == "" {
		service = "general"
	}
	return &SessionContext{
		IP:         ip,
		Service:    service,
		Epoch:      1,
		CreatedAt:  now,
		LastSeenAt: now,
		Events:     make([]normalizer.Event, 0, 20),
	}
}

func (s *SessionContext) Key() string {
	return fmt.Sprintf("%s|%s", s.IP, s.Service)
}

func (s *SessionContext) CorrelationKey() string {
	return fmt.Sprintf("%s|%s|epoch-%d", s.IP, s.Service, s.Epoch)
}

func (s *SessionContext) AddEvent(ev normalizer.Event, maxEvents int, now time.Time) {
	s.LastSeenAt = now
	s.Events = append(s.Events, ev)
	if maxEvents > 0 && len(s.Events) > maxEvents {
		s.Events = s.Events[len(s.Events)-maxEvents:]
	}
}

func (s *SessionContext) BuildContext() string {
	if len(s.Events) == 0 {
		return "No behavior recorded."
	}

	var sb strings.Builder
	for i, ev := range s.Events {
		sanitizedUser := SanitizeLogField(ev.User, 64)
		sanitizedPath := SanitizeLogField(ev.Path, 150)
		sanitizedAction := SanitizeLogField(ev.Action, 64)
		sanitizedService := SanitizeLogField(ev.Service, 32)
		sanitizedIP := SanitizeLogField(ev.IP, 45)

		line := fmt.Sprintf("(%d) At %s, IP %s performed service=%s action=%s status=%s user=%s path=%s\n",
			i+1,
			ev.TS.Format("15:04:05.000"),
			sanitizedIP,
			sanitizedService,
			sanitizedAction,
			ev.Status,
			sanitizedUser,
			sanitizedPath,
		)
		sb.WriteString(line)
	}
	return sb.String()
}

type SessionContextManagerConfig struct {
	IdleTTL             time.Duration
	HardTTL              time.Duration
	MaxSessions         int
	MaxEventsPerSession int
}

// SessionContextManager manages isolated session contexts per IP|Service with Idle TTL, Hard TTL Epoch Rollover, and LRU Eviction.
type SessionContextManager struct {
	mu                  sync.Mutex
	config              SessionContextManagerConfig
	sessions            map[string]*SessionContext
	lruOrder            []string
	EvictionsTotal      int64
	RolloversTotal      int64
	ExpiredTotal        int64
}

func NewSessionContextManager(config SessionContextManagerConfig) *SessionContextManager {
	if config.IdleTTL <= 0 {
		config.IdleTTL = 10 * time.Minute
	}
	if config.HardTTL <= 0 {
		config.HardTTL = 30 * time.Minute
	}
	if config.MaxSessions <= 0 {
		config.MaxSessions = 1000
	}
	if config.MaxEventsPerSession <= 0 {
		config.MaxEventsPerSession = 20
	}

	return &SessionContextManager{
		config:   config,
		sessions: make(map[string]*SessionContext),
		lruOrder: make([]string, 0, config.MaxSessions),
	}
}

// ProcessEvent routes a normalized event to its isolated IP|Service session context, enforcing TTLs and LRU eviction.
func (m *SessionContextManager) ProcessEvent(ev normalizer.Event, now time.Time) *SessionContext {
	m.mu.Lock()
	defer m.mu.Unlock()

	service := ev.Service
	if service == "" {
		service = "general"
	}
	key := fmt.Sprintf("%s|%s", ev.IP, service)

	session, exists := m.sessions[key]
	if exists {
		// 1. Check Idle TTL: if last seen > IdleTTL, expire and reset session
		if now.Sub(session.LastSeenAt) > m.config.IdleTTL {
			m.ExpiredTotal++
			session = NewSessionContext(ev.IP, service, now)
			m.sessions[key] = session
		} else if now.Sub(session.CreatedAt) > m.config.HardTTL {
			// 2. Check Hard TTL: Epoch Rollover to retain continuity without infinite memory growth
			m.RolloversTotal++
			session.Epoch++
			session.CreatedAt = now
			// Retain last 5 events for continuity context
			if len(session.Events) > 5 {
				session.Events = session.Events[len(session.Events)-5:]
			}
		}
	} else {
		// 3. Create new session, enforce MaxSessions LRU eviction
		if len(m.sessions) >= m.config.MaxSessions {
			m.evictOldestLocked()
		}
		session = NewSessionContext(ev.IP, service, now)
		m.sessions[key] = session
	}

	session.AddEvent(ev, m.config.MaxEventsPerSession, now)
	m.touchLRULocked(key)

	return session
}

func (m *SessionContextManager) ActiveSessionsCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

func (m *SessionContextManager) touchLRULocked(key string) {
	for i, k := range m.lruOrder {
		if k == key {
			m.lruOrder = append(m.lruOrder[:i], m.lruOrder[i+1:]...)
			break
		}
	}
	m.lruOrder = append(m.lruOrder, key)
}

func (m *SessionContextManager) evictOldestLocked() {
	if len(m.lruOrder) == 0 {
		return
	}
	oldestKey := m.lruOrder[0]
	m.lruOrder = m.lruOrder[1:]
	delete(m.sessions, oldestKey)
	m.EvictionsTotal++
}

// BehaviorContextBuilder is preserved for legacy single-window compatibility.
type BehaviorContextBuilder struct {
	windowSize int
	events     []normalizer.Event
}

func NewBehaviorContextBuilder(windowSize int) *BehaviorContextBuilder {
	if windowSize <= 0 {
		windowSize = 10
	}
	return &BehaviorContextBuilder{
		windowSize: windowSize,
		events:     make([]normalizer.Event, 0, windowSize),
	}
}

func (b *BehaviorContextBuilder) AddEvent(ev normalizer.Event) {
	b.events = append(b.events, ev)
	if len(b.events) > b.windowSize {
		b.events = b.events[1:]
	}
}

func (b *BehaviorContextBuilder) Clear() {
	b.events = b.events[:0]
}

func (b *BehaviorContextBuilder) BuildContext() string {
	if len(b.events) == 0 {
		return "No behavior recorded."
	}

	var sb strings.Builder
	for i, ev := range b.events {
		line := fmt.Sprintf("(%d) At %s, IP %s performed service=%s action=%s status=%s user=%s path=%s\n",
			i+1,
			ev.TS.Format("15:04:05.000"),
			ev.IP,
			ev.Service,
			ev.Action,
			ev.Status,
			ev.User,
			ev.Path,
		)
		sb.WriteString(line)
	}
	return sb.String()
}

func (b *BehaviorContextBuilder) IsFull() bool {
	return len(b.events) >= b.windowSize
}
