package detector

import (
	"fmt"
	"strings"
	"time"

	"go-logshield/internal/normalizer"
)

type WebEnumDetector struct {
	window    time.Duration
	threshold int
	hits      map[string][]time.Time
}

func NewWebEnumDetector(window time.Duration, threshold int) *WebEnumDetector {
	return &WebEnumDetector{
		window:    window,
		threshold: threshold,
		hits:      make(map[string][]time.Time),
	}
}

func isSensitivePath(path string) bool {
	targets := []string{
		"/wp-login",
		"/admin",
		"/.env",
		"phpmyadmin",
	}
	for _, t := range targets {
		if strings.Contains(path, t) {
			return true
		}
	}
	return false
}

func isErrorStatus(status string) bool {
	return status == "401" || status == "403" || status == "404"
}

func (d *WebEnumDetector) Process(ev normalizer.Event) (string, bool) {
	if ev.Service != "web" {
		return "", false
	}
	if ev.IP == "" || ev.Path == "" {
		return "", false
	}
	if !isSensitivePath(ev.Path) || !isErrorStatus(ev.Status) {
		return "", false
	}

	ip := ev.IP
	now := ev.TS
	d.hits[ip] = append(d.hits[ip], now)

	cutoff := now.Add(-d.window)
	list := d.hits[ip]

	j := 0
	for _, t := range list {
		if !t.Before(cutoff) {
			list[j] = t
			j++
		}
	}
	list = list[:j]
	d.hits[ip] = list

	if len(list) >= d.threshold {
		first := list[0]
		last := list[len(list)-1]

		msg := fmt.Sprintf(
			"⚠️ [경고][중간] 웹 경로 스캐닝(열거) 공격 의심\n"+
				"- IP: %s\n"+
				"- 시도 횟수: %d회 (%d초 윈도우)\n"+
				"- 최초 시각: %s\n"+
				"- 마지막 시각: %s\n"+
				"- 설명: 관리자/환경 파일 등 민감 경로에 대한 접근이 반복되었습니다.",
			ip,
			len(list),
			int(d.window.Seconds()),
			first.Format(time.RFC3339),
			last.Format(time.RFC3339),
		)

		d.hits[ip] = nil
		return msg, true
	}

	return "", false
}
