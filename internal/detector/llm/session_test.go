package llm

import (
	"testing"
	"time"

	"go-logshield/internal/normalizer"
)

func TestSessionContextManager_IsolationAndRollover(t *testing.T) {
	mgr := NewSessionContextManager(SessionContextManagerConfig{
		IdleTTL:             5 * time.Minute,
		HardTTL:              10 * time.Minute,
		MaxSessions:         2,
		MaxEventsPerSession: 10,
	})

	now := time.Now()

	// 1. Add SSH event for IP A
	evA := normalizer.Event{TS: now, IP: "192.168.1.50", Service: "ssh", Action: "login", Status: "failed", User: "root"}
	sessA1 := mgr.ProcessEvent(evA, now)
	if sessA1.CorrelationKey() != "192.168.1.50|ssh|epoch-1" {
		t.Errorf("expected key 192.168.1.50|ssh|epoch-1, got %s", sessA1.CorrelationKey())
	}

	// 2. Add Web event for IP A (should isolate into separate web session)
	evAWeb := normalizer.Event{TS: now, IP: "192.168.1.50", Service: "web", Action: "get", Status: "404", Path: "/admin"}
	sessAWeb := mgr.ProcessEvent(evAWeb, now)
	if sessAWeb.CorrelationKey() != "192.168.1.50|web|epoch-1" {
		t.Errorf("expected key 192.168.1.50|web|epoch-1, got %s", sessAWeb.CorrelationKey())
	}

	// Verify events are isolated
	if len(sessA1.Events) != 1 || sessA1.Events[0].Service != "ssh" {
		t.Errorf("SSH session event isolation failed")
	}
	if len(sessAWeb.Events) != 1 || sessAWeb.Events[0].Service != "web" {
		t.Errorf("Web session event isolation failed")
	}

	// 3. Keep session active with events every 3m (within 5m IdleTTL), then check HardTTL rollover at 11m (exceeding 10m HardTTL)
	mgr.ProcessEvent(evA, now.Add(3*time.Minute))
	mgr.ProcessEvent(evA, now.Add(6*time.Minute))
	mgr.ProcessEvent(evA, now.Add(9*time.Minute))

	futureTime := now.Add(11 * time.Minute)
	sessA2 := mgr.ProcessEvent(evA, futureTime)
	if sessA2.Epoch != 2 {
		t.Errorf("expected Epoch 2 after Hard TTL, got %d", sessA2.Epoch)
	}
	if sessA2.CorrelationKey() != "192.168.1.50|ssh|epoch-2" {
		t.Errorf("expected key 192.168.1.50|ssh|epoch-2, got %s", sessA2.CorrelationKey())
	}
}

func TestCalculateAnomalyScore(t *testing.T) {
	now := time.Now()
	// Create 10 failed logins (should be capped at 10 score) targeting 4 distinct users (capped at 6 score)
	events := make([]normalizer.Event, 0)
	users := []string{"root", "admin", "user1", "user2"}
	for i := 0; i < 10; i++ {
		events = append(events, normalizer.Event{
			TS:      now,
			IP:      "192.168.1.50",
			Service: "ssh",
			Action:  "login",
			Status:  "failed",
			User:    users[i%len(users)],
		})
	}

	stats := CalculateAnomalyScore(events)
	if stats.FailedLoginScore != 10 {
		t.Errorf("expected FailedLoginScore 10 (capped), got %d", stats.FailedLoginScore)
	}
	if stats.DistinctUserScore != 6 {
		t.Errorf("expected DistinctUserScore 6 (capped), got %d", stats.DistinctUserScore)
	}
	if stats.TotalScore != 16 {
		t.Errorf("expected TotalScore 16, got %d", stats.TotalScore)
	}
	if stats.TotalScore > 32 {
		t.Errorf("TotalScore must not exceed max 32 points")
	}
}

func TestAnomalyEvaluator_DeduplicationAndCooldown(t *testing.T) {
	evaluator := NewAnomalyEvaluator(AnomalyEvaluatorConfig{
		Threshold:         7,
		PreInferenceTTL:   30 * time.Second,
		PostAlertCooldown: 60 * time.Second,
	})

	now := time.Now()
	sess := NewSessionContext("192.168.1.50", "ssh", now)
	for i := 0; i < 4; i++ {
		sess.AddEvent(normalizer.Event{
			TS:      now,
			IP:      "192.168.1.50",
			Service: "ssh",
			Action:  "login",
			Status:  "failed",
			User:    "root",
		}, 20, now)
	}

	// 1. First evaluation: score is 8 (>= threshold 7) -> Should return true
	shouldEval, stats, fp := evaluator.ShouldEvaluate(sess, false, now)
	if !shouldEval {
		t.Errorf("expected ShouldEvaluate=true for score %d", stats.TotalScore)
	}

	// 2. Immediate second evaluation with same context -> Should return false (Pre-inference deduplication)
	shouldEval2, _, _ := evaluator.ShouldEvaluate(sess, false, now)
	if shouldEval2 {
		t.Errorf("expected ShouldEvaluate=false on duplicate context fingerprint %s", fp)
	}

	// 3. Post-inference alert cooldown check
	if !evaluator.ShouldAlert(sess.CorrelationKey(), "T1110", "high", now) {
		t.Errorf("expected ShouldAlert=true for first alert")
	}

	// Immediate second alert for same key -> Should return false
	if evaluator.ShouldAlert(sess.CorrelationKey(), "T1110", "high", now) {
		t.Errorf("expected ShouldAlert=false during cooldown window")
	}
}
