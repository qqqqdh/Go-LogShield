package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go-logshield/internal/detector"
	"go-logshield/internal/normalizer"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nxadm/tail"
)

type Alert struct {
	TS       time.Time `json:"ts"`
	Severity string    `json:"severity"` // 낮음/중간/높음/치명
	Title    string    `json:"title"`
	Message  string    `json:"message"`

	IP      string `json:"ip,omitempty"`
	Service string `json:"service,omitempty"`
	RuleID  string `json:"rule_id,omitempty"`
}

type alertMsg struct{ a Alert }

type viewMode int

const (
	viewList viewMode = iota
	viewDetail
)

type model struct {
	paused   bool
	showHelp bool
	mode     viewMode

	alerts   []Alert
	selected int

	statusLine string

	// 통계(있으면 보기 좋음)
	totalEvents int
	totalAlerts int
}

func initialModel() model {
	return model{
		paused:     false,
		showHelp:   true,
		mode:       viewList,
		alerts:     make([]Alert, 0, 100),
		selected:   0,
		statusLine: "실시간 로그 분석 시작됨 (q 종료, p 일시정지)",
	}
}

type savedMsg struct{ path string }
type errMsg struct{ err error }
type eventCountMsg struct{ n int }

func saveReportCmd(alerts []Alert) tea.Cmd {
	snapshot := make([]Alert, len(alerts))
	copy(snapshot, alerts)

	return func() tea.Msg {
		b, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			return errMsg{err: err}
		}
		path := "report.json"
		if err := os.WriteFile(path, b, 0644); err != nil {
			return errMsg{err: err}
		}
		return savedMsg{path: path}
	}
}

func (m model) Init() tea.Cmd { return nil }

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// 메시지에서 제목/심각도 뽑아내기(현재 detector는 msg string만 주니까 여기서 파싱)
func extractTitleAndSeverity(msg string) (title, severity string) {
	// 예:
	// 🚨 [경고][높음] 로그인 브루트포스 의심
	// ...
	lines := strings.Split(msg, "\n")
	if len(lines) == 0 {
		return "경고", "중간"
	}
	head := strings.TrimSpace(lines[0])

	// severity: [경고][높음] 같이 들어있음
	severity = "중간"
	if i := strings.Index(head, "[경고]["); i >= 0 {
		j := strings.Index(head[i+len("[경고]["):], "]")
		if j >= 0 {
			severity = head[i+len("[경고][") : i+len("[경고][")+j]
		}
	}
	// title: 마지막 "] " 이후
	if k := strings.LastIndex(head, "] "); k >= 0 && k+2 < len(head) {
		title = head[k+2:]
	} else {
		title = head
	}
	return title, severity
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch x := msg.(type) {

	case tea.KeyMsg:
		k := x.String()

		switch k {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "h", "?":
			m.showHelp = !m.showHelp
			return m, nil

		case "p":
			m.paused = !m.paused
			if m.paused {
				m.statusLine = "⏸ 일시정지됨 (p로 재개) — 경고는 잠깐 멈춤"
			} else {
				m.statusLine = "▶ 분석 재개됨"
			}
			return m, nil

		case "c":
			m.alerts = nil
			m.selected = 0
			m.mode = viewList
			m.totalEvents = 0
			m.totalAlerts = 0
			m.statusLine = "🧹 초기화 완료"
			return m, nil

		case "s":
			if len(m.alerts) == 0 {
				m.statusLine = "저장할 경고가 없습니다."
				return m, nil
			}
			m.statusLine = "💾 report.json 저장 중..."
			return m, saveReportCmd(m.alerts)

		case "esc":
			if m.mode == viewDetail {
				m.mode = viewList
				m.statusLine = "리스트로 돌아옴"
			}
			return m, nil

		case "enter":
			if len(m.alerts) == 0 {
				return m, nil
			}
			if m.mode == viewList {
				m.mode = viewDetail
			} else {
				m.mode = viewList
			}
			return m, nil
		}

		if m.mode == viewList && len(m.alerts) > 0 {
			switch k {
			case "up", "k":
				m.selected = clamp(m.selected-1, 0, len(m.alerts)-1)
				return m, nil
			case "down", "j":
				m.selected = clamp(m.selected+1, 0, len(m.alerts)-1)
				return m, nil
			case "g":
				m.selected = 0
				return m, nil
			case "G":
				m.selected = len(m.alerts) - 1
				return m, nil
			}
		}

	case alertMsg:
		if m.paused {
			return m, nil
		}
		m.totalAlerts++
		// 최대 100개만 보관(메모리/화면 관리)
		if len(m.alerts) >= 100 {
			// 오래된 것 제거(앞에서 하나 제거)
			m.alerts = m.alerts[1:]
			// selected도 조정
			m.selected = clamp(m.selected-1, 0, len(m.alerts)-1)
		}
		m.alerts = append(m.alerts, x.a)
		m.selected = clamp(m.selected, 0, len(m.alerts)-1)
		m.statusLine = fmt.Sprintf("🚨 새 경고: %s", x.a.Title)
		return m, nil

	case eventCountMsg:
		if !m.paused {
			m.totalEvents += x.n
		}
		return m, nil

	case savedMsg:
		m.statusLine = fmt.Sprintf("✅ 저장 완료: %s", x.path)
		return m, nil

	case errMsg:
		m.statusLine = fmt.Sprintf("❌ 오류: %v", x.err)
		return m, nil
	}

	return m, nil
}

func (m model) View() string {
	state := "RUNNING"
	if m.paused {
		state = "PAUSED"
	}

	header := ""
	header += "Go-LogShield TUI (실시간 로그 분석)\n"
	header += fmt.Sprintf("상태: %s | 이벤트: %d | 경고: %d | 모드: %s\n",
		state, m.totalEvents, m.totalAlerts,
		map[viewMode]string{viewList: "LIST", viewDetail: "DETAIL"}[m.mode],
	)
	if m.statusLine != "" {
		header += m.statusLine + "\n"
	}
	header += "--------------------------------------------------\n"

	help := ""
	if m.showHelp {
		help += "단축키\n"
		help += "  q: 종료   p: 일시정지/재개   c: 초기화   s: report.json 저장\n"
		help += "  h/?: 도움말 토글   ↑/k ↓/j: 이동   enter: 상세보기 토글   esc: 리스트로\n"
		help += "  g: 맨위   G: 맨아래\n"
		help += "--------------------------------------------------\n"
	}

	if len(m.alerts) == 0 {
		return header + help + "(아직 경고 없음 — 로그를 계속 따라가는 중)\n"
	}

	if m.mode == viewList {
		out := header + help
		out += "최근 경고 목록 (enter로 상세보기)\n\n"

		// 최신이 아래에 쌓이지만 보기 편하게 최근순 역순 출력
		for i := 0; i < len(m.alerts); i++ {
			idx := len(m.alerts) - 1 - i
			a := m.alerts[idx]

			cursor := "  "
			if idx == m.selected {
				cursor = "> "
			}

			out += fmt.Sprintf("%s[%s] %s  (%s)\n",
				cursor, a.Severity, a.Title, a.TS.Format("15:04:05"),
			)
		}
		out += "\n"
		return out
	}

	// DETAIL
	a := m.alerts[m.selected]
	out := header + help
	out += "상세 보기 (esc 또는 enter로 돌아가기)\n\n"
	out += fmt.Sprintf("🚨 제목: %s\n", a.Title)
	out += fmt.Sprintf("등급: %s\n", a.Severity)
	out += fmt.Sprintf("시간: %s\n", a.TS.Format(time.RFC3339))
	if a.IP != "" {
		out += fmt.Sprintf("IP: %s\n", a.IP)
	}
	if a.Service != "" {
		out += fmt.Sprintf("서비스: %s\n", a.Service)
	}
	if a.RuleID != "" {
		out += fmt.Sprintf("RuleID: %s\n", a.RuleID)
	}
	out += "\n원문 메시지\n"
	out += a.Message + "\n"
	return out
}

// --- 실시간 tail + 분석 파이프라인 ---
// p.Send(...)로 TUI에 메시지 push
func startRealtimePipeline(p *tea.Program) error {
	paths, err := filepath.Glob("./logs/*.log")
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		// logs 폴더 없어도 실행은 되게 하고, 상태 라인으로 안내만 함
		p.Send(errMsg{err: fmt.Errorf("./logs/*.log 파일을 찾지 못했습니다. logs 폴더를 만들고 로그를 생성해보세요.")})
		return nil
	}

	// detectors (TUI 프로세스 안에서 단일 고루틴으로 호출하면 경쟁조건 없이 안전)
	bruteForceDetector := detector.NewBruteForceDetector(detector.BruteForceConfig{
		Window:    20 * time.Second,
		Threshold: 5,
	})
	sshBruteForceDetector := detector.NewSSHBruteForceDetector(30*time.Second, 6)
	webEnumDetector := detector.NewWebEnumDetector(30*time.Second, 4)

	// 각 파일 tailer 실행
	for _, path := range paths {
		path := path

		go func() {
			// Windows에서도 잘 따라가게 Poll + ReOpen 권장
			t, err := tail.TailFile(path, tail.Config{
				Follow:    true,
				ReOpen:    true,
				MustExist: false,
				Poll:      true,
				Logger:    tail.DiscardingLogger,
			})
			if err != nil {
				p.Send(errMsg{err: fmt.Errorf("tail 실패 (%s): %w", path, err)})
				return
			}

			for line := range t.Lines {
				if line == nil {
					continue
				}
				raw := strings.TrimSpace(line.Text)
				if raw == "" {
					continue
				}

				// 이벤트 카운트 +1
				p.Send(eventCountMsg{n: 1})

				ev, err := normalizer.ParseLine(raw)
				if err != nil {
					// 파싱 에러는 상태라인만 살짝(도배 방지)
					p.Send(errMsg{err: fmt.Errorf("parse error (%s): %v", path, err)})
					continue
				}

				// 1) auth brute force
				if msg, ok := bruteForceDetector.Process(ev); ok {
					title, sev := extractTitleAndSeverity(msg)
					p.Send(alertMsg{a: Alert{
						TS:       time.Now(),
						Severity: sev,
						Title:    title,
						Message:  msg,
						IP:       ev.IP,
						Service:  ev.Service,
						RuleID:   "BRUTE_FORCE_LOGIN",
					}})
				}

				// 2) ssh brute force
				if msg, ok := sshBruteForceDetector.Process(ev); ok {
					title, sev := extractTitleAndSeverity(msg)
					p.Send(alertMsg{a: Alert{
						TS:       time.Now(),
						Severity: sev,
						Title:    title,
						Message:  msg,
						IP:       ev.IP,
						Service:  ev.Service,
						RuleID:   "SSH_BRUTE_FORCE",
					}})
				}

				// 3) web enumeration
				if msg, ok := webEnumDetector.Process(ev); ok {
					title, sev := extractTitleAndSeverity(msg)
					p.Send(alertMsg{a: Alert{
						TS:       time.Now(),
						Severity: sev,
						Title:    title,
						Message:  msg,
						IP:       ev.IP,
						Service:  ev.Service,
						RuleID:   "WEB_ENUMERATION",
					}})
				}
			}
		}()
	}

	// 시작 안내
	p.Send(errMsg{err: fmt.Errorf("실시간 tail 시작: %d개 파일 (./logs/*.log)", len(paths))})
	return nil
}

func main() {
	// AltScreen: 전용 터미널 느낌(전체 화면)
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())

	// 실시간 파이프라인 시작(백그라운드 goroutine들이 p.Send로 화면 갱신)
	go func() {
		_ = startRealtimePipeline(p)
	}()

	if _, err := p.Run(); err != nil {
		panic(err)
	}
}
