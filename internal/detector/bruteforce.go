package detector

import (
	"fmt"
	"sync"
	"time"

	"go-logshield/internal/normalizer"
)

// maxTrackedIPs: 맵 크기 상한 — 이 이상의 고유 IP는 추적하지 않아 메모리 고갈을 방지합니다.
const maxTrackedIPs = 10_000

type BruteForceConfig struct {
	Window    time.Duration
	Threshold int
}

type BruteForceDetector struct {
	mu       sync.Mutex
	cfg      BruteForceConfig
	failures map[string][]time.Time
	blocked  map[string]time.Time
}

func NewBruteForceDetector(cfg BruteForceConfig) *BruteForceDetector {
	return &BruteForceDetector{
		cfg:      cfg,
		failures: make(map[string][]time.Time),
		blocked:  make(map[string]time.Time),
	}
}

func (d *BruteForceDetector) Process(ev normalizer.Event) (Result, bool) {
	// match: service=auth action=login status=FAIL group_by=ip
	if ev.Service != "auth" || ev.Action != "login" || ev.Status != "FAIL" {
		return Result{}, false
	}
	if ev.IP == "" {
		return Result{}, false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	ip := ev.IP
	now := ev.TS

	if blockTime, exists := d.blocked[ip]; exists {
		if now.Sub(blockTime) < d.cfg.Window {
			return Result{}, false
		}
		delete(d.blocked, ip)
	}

	// 1) 맵 크기 상한 초과 시 새 IP 무시 (DoS 방지)
	if _, exists := d.failures[ip]; !exists && len(d.failures) >= maxTrackedIPs {
		return Result{}, false
	}
	// 2) append current failure time
	d.failures[ip] = append(d.failures[ip], now)

	// 3) evict timestamps outside window
	cutoff := now.Add(-d.cfg.Window)
	tsList := d.failures[ip]

	// keep only ts >= cutoff
	j := 0
	for _, t := range tsList {
		if !t.Before(cutoff) {
			tsList[j] = t
			j++
		}
	}
	tsList = tsList[:j]
	d.failures[ip] = tsList

	// 4) threshold check
	if len(tsList) >= d.cfg.Threshold {
		first := tsList[0]
		last := tsList[len(tsList)-1]

		const ruleID = "BRUTE_FORCE_LOGIN"
		const sev = "high"

		msg := fmt.Sprintf(
			"🚨 [경고][%s] %s\n- IP: %s\n- 실패 횟수: %d회 (%d초 윈도우)\n- 최초 시각: %s\n- 마지막 시각: %s\n- 설명: %s",
			severityKR(sev),
			ruleTitleKR(ruleID),
			ip,
			len(tsList),
			int(d.cfg.Window.Seconds()),
			first.UTC().Format(time.RFC3339),
			last.UTC().Format(time.RFC3339),
			ruleDescKR(ruleID),
		)

		delete(d.failures, ip)
		d.blocked[ip] = now

		return Result{
			RuleID:   ruleID,
			Title:    ruleTitleKR(ruleID),
			Severity: severityKR(sev),
			Message:  msg,
			IP:       ip,
			Service:  ev.Service,
		}, true
	}

	return Result{}, false
}
func severityKR(sev string) string {
	switch sev {
	case "critical":
		return "치명"
	case "high":
		return "높음"
	case "medium":
		return "중간"
	case "low":
		return "낮음"
	default:
		return sev
	}
}

func ruleTitleKR(ruleID string) string {
	switch ruleID {
	case "BRUTE_FORCE_LOGIN":
		return "로그인 브루트포스 의심"
	default:
		return ruleID
	}
}

func ruleDescKR(ruleID string) string {
	switch ruleID {
	case "BRUTE_FORCE_LOGIN":
		return "동일 IP에서 짧은 시간에 로그인 실패가 반복되었습니다."
	default:
		return ""
	}
}
