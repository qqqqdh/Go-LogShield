package detector

import (
	"fmt"
	"sync"
	"time"

	"go-logshield/internal/normalizer"
)

type SSHBruteForceDetector struct {
	mu        sync.Mutex
	window    time.Duration
	threshold int
	failures  map[string][]time.Time
}

func NewSSHBruteForceDetector(window time.Duration, threshold int) *SSHBruteForceDetector {
	return &SSHBruteForceDetector{
		window:    window,
		threshold: threshold,
		failures:  make(map[string][]time.Time),
	}
}

func (d *SSHBruteForceDetector) Process(ev normalizer.Event) (Result, bool) {
	if ev.Service != "ssh" || ev.Action != "auth" || ev.Status != "FAIL" {
		return Result{}, false
	}
	if ev.IP == "" {
		return Result{}, false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	ip := ev.IP
	now := ev.TS

	// 맵 크기 상한 초과 시 새 IP 무시 (DoS 방지)
	if _, exists := d.failures[ip]; !exists && len(d.failures) >= maxTrackedIPs {
		return Result{}, false
	}

	d.failures[ip] = append(d.failures[ip], now)

	cutoff := now.Add(-d.window)
	list := d.failures[ip]

	j := 0
	for _, t := range list {
		if !t.Before(cutoff) {
			list[j] = t
			j++
		}
	}
	list = list[:j]
	d.failures[ip] = list

	if len(list) >= d.threshold {
		first := list[0]
		last := list[len(list)-1]

		const ruleID = "SSH_BRUTE_FORCE"
		msg := fmt.Sprintf(
			"🚨 [경고][높음] SSH 브루트포스 공격 의심\n"+
				"- IP: %s\n"+
				"- 실패 횟수: %d회 (%d초 윈도우)\n"+
				"- 최초 시각: %s\n"+
				"- 마지막 시각: %s\n"+
				"- 설명: 동일 IP에서 SSH 인증 실패가 짧은 시간에 반복되었습니다.",
			ip,
			len(list),
			int(d.window.Seconds()),
			first.Format(time.RFC3339),
			last.Format(time.RFC3339),
		)

		delete(d.failures, ip)
		return Result{
			RuleID:   ruleID,
			Title:    "SSH 브루트포스 공격 의심",
			Severity: "높음",
			Message:  msg,
			IP:       ip,
			Service:  ev.Service,
		}, true
	}

	return Result{}, false
}
