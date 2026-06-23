//go:build demo

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type Alert struct {
	TS       time.Time `json:"ts"`
	Severity string    `json:"severity"` // "낮음/중간/높음/치명"
	Title    string    `json:"title"`
	Message  string    `json:"message"`

	// 확장용(나중에 detector에서 채울 수 있음)
	IP      string `json:"ip,omitempty"`
	RuleID  string `json:"rule_id,omitempty"`
	Service string `json:"service,omitempty"`
}

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
	selected int // alerts index

	statusLine string // 저장 완료/에러 같은 상태 메시지
}

func initialModel() model {
	return model{
		paused:     false,
		showHelp:   true,
		mode:       viewList,
		alerts:     make([]Alert, 0, 50),
		selected:   0,
		statusLine: "",
	}
}

// --- tick (데모용 이벤트 생성) ---
type tickMsg time.Time

func tick() tea.Cmd {
	return tea.Tick(300*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// --- 저장 결과 메시지 ---
type savedMsg struct{ path string }
type errMsg struct{ err error }

func saveReportCmd(alerts []Alert) tea.Cmd {
	snapshot := make([]Alert, len(alerts))
	copy(snapshot, alerts)

	return func() tea.Msg {
		b, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			return errMsg{err: err}
		}
		path := "report.json"
		if err := os.WriteFile(path, b, 0600); err != nil {
			return errMsg{err: err}
		}
		return savedMsg{path: path}
	}
}

func (m model) Init() tea.Cmd {
	return tick()
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch x := msg.(type) {

	case tea.KeyMsg:
		k := x.String()

		// --- 글로벌 단축키 ---
		switch k {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "h", "?":
			m.showHelp = !m.showHelp
			return m, nil
		case "p":
			m.paused = !m.paused
			if m.paused {
				m.statusLine = "⏸ 일시정지됨 (p로 재개)"
			} else {
				m.statusLine = "▶ 분석 재개됨"
			}
			return m, nil
		case "c":
			m.alerts = nil
			m.selected = 0
			m.mode = viewList
			m.statusLine = "🧹 경고 목록 초기화"
			return m, nil
		case "s":
			// 현재까지 경고를 report.json으로 저장
			if len(m.alerts) == 0 {
				m.statusLine = "저장할 경고가 없습니다."
				return m, nil
			}
			m.statusLine = "💾 report.json 저장 중..."
			return m, saveReportCmd(m.alerts)
		case "esc":
			// 상세보기에서 리스트로 돌아가기
			if m.mode == viewDetail {
				m.mode = viewList
				m.statusLine = "리스트로 돌아옴"
			}
			return m, nil
		case "enter":
			// 선택된 항목 상세 보기 토글
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

		// --- 리스트 탐색 단축키(리스트 모드에서만) ---
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

	case tickMsg:
		if !m.paused {
			if len(m.alerts) < 50 {
				sev := "중간"
				title := "웹 경로 스캐닝 의심(데모)"
				msg := "민감 경로에 대한 접근이 반복되었습니다."

				// 3개 중 하나를 랜덤처럼 바꾸기(간단히 시간으로)
				n := int(time.Now().UnixNano() % 3)

				switch n {
				case 0:
					sev = "높음"
					title = "로그인 브루트포스 의심(데모)"
					msg = "동일 IP에서 로그인 실패가 짧은 시간에 반복되었습니다."
				case 1:
					sev = "높음"
					title = "SSH 브루트포스 의심(데모)"
					msg = "동일 IP에서 SSH 인증 실패가 짧은 시간에 반복되었습니다."
				}

				m.alerts = append(m.alerts, Alert{
					TS:       time.Now(),
					Severity: sev,
					Title:    title,
					Message:  msg,
					IP:       "198.51.100.23",
					RuleID:   "DEMO_RULE",
					Service:  "demo",
				})

				m.selected = clamp(m.selected, 0, len(m.alerts)-1)
			}
		}
		return m, tick()

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
	header := "Go-LogShield TUI\n"
	state := "RUNNING"
	if m.paused {
		state = "PAUSED"
	}
	header += fmt.Sprintf("상태: %s | 경고 수: %d | 모드: %s\n",
		state, len(m.alerts), map[viewMode]string{viewList: "LIST", viewDetail: "DETAIL"}[m.mode],
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
		return header + help + "(아직 경고 없음)\n"
	}

	// 리스트 모드
	if m.mode == viewList {
		out := header + help
		out += "최근 경고 목록 (enter로 상세보기)\n\n"

		// 최신이 아래로 쌓이는 대신, 화면에서는 “위에서 아래로” 보기 편하게 최근순 역순 출력
		// 하지만 selected는 실제 slice index 기준이므로, 출력 시 매핑해줌.
		// 출력 i번째 항목 -> 실제 index = len(alerts)-1-i
		for i := 0; i < len(m.alerts); i++ {
			idx := len(m.alerts) - 1 - i
			a := m.alerts[idx]

			cursor := "  "
			if idx == m.selected {
				cursor = "> "
			}

			out += fmt.Sprintf("%s[%s] %s  (%s)\n",
				cursor,
				a.Severity,
				a.Title,
				a.TS.Format("15:04:05"),
			)
		}
		out += "\n"
		return out
	}

	// 상세 모드
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
	out += "\n설명\n"
	out += fmt.Sprintf("  %s\n", a.Message)
	out += "\n"
	return out
}

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		panic(err)
	}
}
