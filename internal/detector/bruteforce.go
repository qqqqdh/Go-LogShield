package detector

import (
	"fmt"
	"time"

	"go-logshield/internal/normalizer"
)

type BruteForceConfig struct {
	Window    time.Duration
	Threshold int
}

type BruteForceDetector struct {
	cfg BruteForceConfig

	// ip -> list of failure timestamps (sliding window)
	failures map[string][]time.Time
}

func NewBruteForceDetector(cfg BruteForceConfig) *BruteForceDetector {
	return &BruteForceDetector{
		cfg:      cfg,
		failures: make(map[string][]time.Time),
	}
}

// Process returns (alertMessage, true) when alert triggers.
func (d *BruteForceDetector) Process(ev normalizer.Event) (string, bool) {
	// match: service=auth action=login status=FAIL group_by=ip
	if ev.Service != "auth" || ev.Action != "login" || ev.Status != "FAIL" {
		return "", false
	}
	if ev.IP == "" {
		return "", false
	}

	ip := ev.IP
	now := ev.TS

	// 1) append current failure time
	d.failures[ip] = append(d.failures[ip], now)

	// 2) evict timestamps outside window
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

	// 3) threshold check
	if len(tsList) >= d.cfg.Threshold {
		first := tsList[0]
		last := tsList[len(tsList)-1]

		ruleID := "BRUTE_FORCE_LOGIN"
		sev := "high"

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

		// (중요) 같은 윈도우에서 알림이 계속 도배되는 걸 막기 위해 리셋
		// 가장 단순한 억제(suppress) 방식
		d.failures[ip] = nil

		return msg, true
	}

	return "", false
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
