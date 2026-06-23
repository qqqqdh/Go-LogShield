package detector

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"go-logshield/internal/normalizer"
)

type WebEnumDetector struct {
	mu        sync.Mutex
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
		"/.git",
		"/backup",
		"/config",
		"/api/v1",
		"/actuator",
		"/server-status",
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

func (d *WebEnumDetector) Process(ev normalizer.Event) (Result, bool) {
	if ev.Service != "web" {
		return Result{}, false
	}
	if ev.IP == "" || ev.Path == "" {
		return Result{}, false
	}
	if !isSensitivePath(ev.Path) || !isErrorStatus(ev.Status) {
		return Result{}, false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	ip := ev.IP
	now := ev.TS

	// 맵 크기 상한 초과 시 새 IP 무시 (DoS 방지)
	if _, exists := d.hits[ip]; !exists && len(d.hits) >= maxTrackedIPs {
		return Result{}, false
	}

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

		const ruleID = "WEB_ENUMERATION"
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

		delete(d.hits, ip)
		return Result{
			RuleID:   ruleID,
			Title:    "웹 경로 스캐닝(열거) 공격 의심",
			Severity: "중간",
			Message:  msg,
			IP:       ip,
			Service:  ev.Service,
		}, true
	}

	return Result{}, false
}
