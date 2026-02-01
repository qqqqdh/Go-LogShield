package detector

import (
	"fmt"
	"time"

	"go-logshield/internal/normalizer"
)

type SSHBruteForceDetector struct {
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

func (d *SSHBruteForceDetector) Process(ev normalizer.Event) (string, bool) {
	if ev.Service != "ssh" || ev.Action != "auth" || ev.Status != "FAIL" {
		return "", false
	}
	if ev.IP == "" {
		return "", false
	}

	ip := ev.IP
	now := ev.TS
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

		d.failures[ip] = nil
		return msg, true
	}

	return "", false
}
