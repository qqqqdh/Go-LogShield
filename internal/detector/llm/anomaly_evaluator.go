package llm

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	"go-logshield/internal/normalizer"
)

type AnomalyStats struct {
	FailedLoginCount          int
	DistinctUserCount         int
	SensitivePathCount        int
	HTTP404Count              int
	SuccessAfterFailures      bool
	FailedLoginScore          int
	DistinctUserScore         int
	SensitivePathScore        int
	HTTP404Score              int
	SuccessAfterFailuresScore int
	TotalScore                int // Max 32
}

func CalculateAnomalyScore(events []normalizer.Event) AnomalyStats {
	stats := AnomalyStats{}
	failedUsers := make(map[string]bool)
	hasFailed := false
	hasSuccessAfterFailed := false

	sensitiveKeywords := []string{
		"/.env", "/admin", "/config", "/backup", "/wp-login", "/.git",
		"/phpmyadmin", "/shadow", "/etc/passwd", "/cmd", "/exec",
	}

	for _, ev := range events {
		statusLower := strings.ToLower(ev.Status)
		pathLower := strings.ToLower(ev.Path)

		isFail := statusLower == "failed" || statusLower == "401" || statusLower == "fail"
		isSuccess := statusLower == "success" || statusLower == "200" || statusLower == "ok"

		if isFail {
			stats.FailedLoginCount++
			hasFailed = true
			if ev.User != "" {
				failedUsers[ev.User] = true
			}
		}

		if hasFailed && isSuccess {
			hasSuccessAfterFailed = true
		}

		if statusLower == "404" {
			stats.HTTP404Count++
		}

		for _, kw := range sensitiveKeywords {
			if strings.Contains(pathLower, kw) {
				stats.SensitivePathCount++
				break
			}
		}
	}

	stats.DistinctUserCount = len(failedUsers)
	stats.SuccessAfterFailures = hasSuccessAfterFailed

	// Apply capped scores
	stats.FailedLoginScore = minInt(stats.FailedLoginCount, 5) * 2     // max 10
	stats.DistinctUserScore = minInt(stats.DistinctUserCount, 3) * 2   // max 6
	stats.SensitivePathScore = minInt(stats.SensitivePathCount, 2) * 3 // max 6
	stats.HTTP404Score = minInt(stats.HTTP404Count, 5) * 1            // max 5
	if stats.SuccessAfterFailures {
		stats.SuccessAfterFailuresScore = 5 // max 5
	}

	stats.TotalScore = stats.FailedLoginScore + stats.DistinctUserScore + stats.SensitivePathScore + stats.HTTP404Score + stats.SuccessAfterFailuresScore
	return stats
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type AnomalyEvaluatorConfig struct {
	Threshold         int           // Default 7 (out of max 32)
	PreInferenceTTL   time.Duration // Default 30s
	PostAlertCooldown time.Duration // Default 60s
}

// AnomalyEvaluator decides when to trigger LLM inference and manages two-stage deduplication and alert cooldown.
type AnomalyEvaluator struct {
	mu                 sync.Mutex
	config             AnomalyEvaluatorConfig
	preInferenceCache  map[string]time.Time
	postInferenceCache map[string]time.Time
}

func NewAnomalyEvaluator(config AnomalyEvaluatorConfig) *AnomalyEvaluator {
	if config.Threshold <= 0 {
		config.Threshold = 7
	}
	if config.PreInferenceTTL <= 0 {
		config.PreInferenceTTL = 30 * time.Second
	}
	if config.PostAlertCooldown <= 0 {
		config.PostAlertCooldown = 60 * time.Second
	}

	return &AnomalyEvaluator{
		config:             config,
		preInferenceCache:  make(map[string]time.Time),
		postInferenceCache: make(map[string]time.Time),
	}
}

// ShouldEvaluate checks if session anomaly score >= threshold (or rule triggered) and handles Stage 1 pre-inference deduplication.
func (e *AnomalyEvaluator) ShouldEvaluate(session *SessionContext, ruleTriggered bool, now time.Time) (bool, AnomalyStats, string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.cleanupCacheLocked(now)

	stats := CalculateAnomalyScore(session.Events)
	if stats.TotalScore < e.config.Threshold && !ruleTriggered {
		return false, stats, ""
	}

	// Compute context fingerprint for Stage 1 Pre-inference deduplication
	ctxText := session.BuildContext()
	fingerprintData := fmt.Sprintf("%s|score:%d|ctx:%s", session.CorrelationKey(), stats.TotalScore, ctxText)
	h := sha256.Sum256([]byte(fingerprintData))
	fingerprint := fmt.Sprintf("%x", h[:8])

	if exp, exists := e.preInferenceCache[fingerprint]; exists && now.Before(exp) {
		// Duplicate context in pre-inference window -> skip LLM evaluation
		return false, stats, fingerprint
	}

	// Record pre-inference trigger
	e.preInferenceCache[fingerprint] = now.Add(e.config.PreInferenceTTL)
	return true, stats, fingerprint
}

// ShouldAlert manages Stage 2 post-inference alert cooldown per correlation key, technique ID, and severity.
func (e *AnomalyEvaluator) ShouldAlert(correlationKey string, techniqueID string, severity string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.cleanupCacheLocked(now)

	alertKey := fmt.Sprintf("%s|%s|%s", correlationKey, techniqueID, strings.ToLower(severity))
	if exp, exists := e.postInferenceCache[alertKey]; exists && now.Before(exp) {
		return false
	}

	cooldown := e.config.PostAlertCooldown
	if strings.ToLower(severity) == "critical" {
		cooldown = 15 * time.Second
	}

	e.postInferenceCache[alertKey] = now.Add(cooldown)
	return true
}

func (e *AnomalyEvaluator) cleanupCacheLocked(now time.Time) {
	for k, exp := range e.preInferenceCache {
		if now.After(exp) {
			delete(e.preInferenceCache, k)
		}
	}
	for k, exp := range e.postInferenceCache {
		if now.After(exp) {
			delete(e.postInferenceCache, k)
		}
	}
}
