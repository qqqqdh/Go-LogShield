package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go-logshield/internal/detector"
	"go-logshield/internal/normalizer"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nxadm/tail"
)

type Alert struct {
	TS       time.Time `json:"ts"`
	Severity string    `json:"severity"`
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
	alerts       []Alert
	selectedIdx  int
	mode         viewMode
	err          error
	paused       bool
	showHelp     bool
	eventCount   int
	alertCount   int
	subChan      chan Alert
}

func initialModel(subChan chan Alert) model {
	return model{
		alerts:      make([]Alert, 0),
		selectedIdx: 0,
		mode:        viewList,
		subChan:     subChan,
	}
}

func (m model) Init() tea.Cmd {
	return waitForNextAlert(m.subChan)
}

func waitForNextAlert(subChan chan Alert) tea.Cmd {
	return func() tea.Msg {
		a := <-subChan
		return alertMsg{a: a}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "p":
			m.paused = !m.paused
		case "c":
			m.alerts = nil
			m.selectedIdx = 0
			m.alertCount = 0
		case "h", "?":
			m.showHelp = !m.showHelp
		case "down", "j":
			if m.selectedIdx < len(m.alerts)-1 {
				m.selectedIdx++
			}
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
		case "enter":
			if len(m.alerts) > 0 {
				if m.mode == viewList {
					m.mode = viewDetail
				} else {
					m.mode = viewList
				}
			}
		case "esc":
			m.mode = viewList
		}

	case alertMsg:
		if !m.paused {
			m.alerts = append(m.alerts, msg.a)
			m.alertCount++
			if m.selectedIdx == len(m.alerts)-2 || len(m.alerts) == 1 {
				m.selectedIdx = len(m.alerts) - 1
			}
		}
		return m, waitForNextAlert(m.subChan)
	}

	return m, nil
}

func (m model) View() string {
	s := "🛡️  Go-LogShield Real-time TUI Monitoring Dashboard\n"
	s += fmt.Sprintf("Alerts Detected: %d | Paused: %v\n", len(m.alerts), m.paused)
	s += "--------------------------------------------------\n"

	if len(m.alerts) == 0 {
		s += "Waiting for incoming log stream and security alerts...\n"
	} else if m.mode == viewList {
		for i, a := range m.alerts {
			cursor := " "
			if i == m.selectedIdx {
				cursor = ">"
			}
			s += fmt.Sprintf("%s [%s] %s (%s) IP:%s\n", cursor, a.Severity, a.Title, a.TS.Format("15:04:05"), a.IP)
		}
	} else if m.mode == viewDetail && m.selectedIdx < len(m.alerts) {
		a := m.alerts[m.selectedIdx]
		s += fmt.Sprintf("=== Alert Detail [%s] ===\nTitle: %s\nTime: %s\nIP: %s\nRule: %s\nMessage: %s\n",
			a.Severity, a.Title, a.TS.Format(time.RFC3339), a.IP, a.RuleID, a.Message)
		s += "\n(Press ESC or ENTER to return to list)\n"
	}

	s += "\nKeys: q: Quit | p: Pause | c: Clear | ↑/↓: Navigate | ENTER: Details\n"
	return s
}

func main() {
	logDir := flag.String("log-dir", "./logs", "Directory containing log files to tail")
	flag.Parse()

	subChan := make(chan Alert, 100)

	// Tail log files in background
	go func() {
		pattern := filepath.Join(*logDir, "*.log")
		files, _ := filepath.Glob(pattern)

		bruteForce := detector.NewBruteForceDetector(detector.BruteForceConfig{Window: 20 * time.Second, Threshold: 5})
		sshBruteForce := detector.NewSSHBruteForceDetector(30*time.Second, 6)
		webEnum := detector.NewWebEnumDetector(30*time.Second, 4)

		for _, file := range files {
			go func(filePath string) {
				t, err := tail.TailFile(filePath, tail.Config{Follow: true, ReOpen: true})
				if err != nil {
					return
				}
				for line := range t.Lines {
					ev, err := normalizer.ParseLine(line.Text)
					if err != nil {
						continue
					}
					if r, ok := bruteForce.Process(ev); ok {
						subChan <- Alert{TS: ev.TS, Severity: r.Severity, Title: r.Title, Message: r.Message, IP: r.IP, RuleID: r.RuleID, Service: r.Service}
					}
					if r, ok := sshBruteForce.Process(ev); ok {
						subChan <- Alert{TS: ev.TS, Severity: r.Severity, Title: r.Title, Message: r.Message, IP: r.IP, RuleID: r.RuleID, Service: r.Service}
					}
					if r, ok := webEnum.Process(ev); ok {
						subChan <- Alert{TS: ev.TS, Severity: r.Severity, Title: r.Title, Message: r.Message, IP: r.IP, RuleID: r.RuleID, Service: r.Service}
					}
				}
			}(file)
		}
	}()

	p := tea.NewProgram(initialModel(subChan))
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
		os.Exit(1)
	}
}
