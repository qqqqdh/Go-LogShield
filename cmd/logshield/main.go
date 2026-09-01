package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"go-logshield/internal/detector"
	"go-logshield/internal/detector/llm"
	"go-logshield/internal/normalizer"
	"go-logshield/internal/pkg/watcher"
)

type FinalReport struct {
	Timestamp         string            `json:"timestamp"`
	RuleBasedAlerts   []detector.Result `json:"rule_based_alerts"`
	LLMICLEvaluations []llm.ICLResult   `json:"llm_icl_evaluations"`
	TotalLogsAnalyzed int               `json:"total_logs_analyzed"`
	ActiveSessions    int               `json:"active_sessions_count"`
}

func main() {
	logDir := flag.String("log-dir", "./logs", "Path to log directory containing .log files")
	enableLLM := flag.Bool("llm", true, "Enable LLaMA 3.1 8B In-Context Learning (ICL) Detector")
	ollamaURL := flag.String("ollama-url", "http://localhost:11434", "Ollama API Endpoint URL")
	llmModel := flag.String("llm-model", "llama3.1:8b", "LLM Model Name for In-Context Learning")
	anomalyThreshold := flag.Int("anomaly-threshold", 7, "Anomaly Score threshold (0-32) to trigger 2nd-stage LLM evaluation")
	idleTTL := flag.Duration("session-idle-ttl", 10*time.Minute, "Session Idle TTL before expiration")
	hardTTL := flag.Duration("session-hard-ttl", 30*time.Minute, "Session Hard TTL before Epoch Rollover")
	maxSessions := flag.Int("max-sessions", 1000, "Maximum active session contexts (LRU Eviction)")
	printPrompt := flag.Bool("print-prompt", false, "Print the full generated LLM prompt to stdout for verification")
	watchMode := flag.Bool("watch", false, "Enable real-time log file tailing mode")
	reportFile := flag.String("report", "report.json", "Output JSON report file path")
	flag.Parse()

	// 1. Locate log files
	pattern := filepath.Join(*logDir, "*.log")
	files, err := filepath.Glob(pattern)
	if err != nil {
		log.Fatal(err)
	}
	if len(files) == 0 {
		log.Fatalf("No log files found in %s", *logDir)
	}

	// 2. Initialize Rule-Based Detectors
	bruteForceDetector := detector.NewBruteForceDetector(detector.BruteForceConfig{
		Window:    20 * time.Second,
		Threshold: 5,
	})
	sshBruteForceDetector := detector.NewSSHBruteForceDetector(30*time.Second, 6)
	webEnumDetector := detector.NewWebEnumDetector(30*time.Second, 4)

	// 3. Initialize Paper-Based LLM In-Context Learning (ICL) Engine & Session Context Manager
	var sessionManager *llm.SessionContextManager
	var anomalyEvaluator *llm.AnomalyEvaluator
	var iclDetector *llm.ICLDetector

	if *enableLLM {
		sessionManager = llm.NewSessionContextManager(llm.SessionContextManagerConfig{
			IdleTTL:             *idleTTL,
			HardTTL:              *hardTTL,
			MaxSessions:         *maxSessions,
			MaxEventsPerSession: 20,
		})
		anomalyEvaluator = llm.NewAnomalyEvaluator(llm.AnomalyEvaluatorConfig{
			Threshold:         *anomalyThreshold,
			PreInferenceTTL:   30 * time.Second,
			PostAlertCooldown: 60 * time.Second,
		})
		iclDetector = llm.NewICLDetector(llm.ICLDetectorConfig{
			OllamaURL: *ollamaURL,
			ModelName: *llmModel,
			Timeout:   5 * time.Second,
		})
		fmt.Printf("🤖 [LogShield Phase 3 & 4] Hybrid LLM Engine Initialized (Model: %s, Anomaly Threshold: %d/32)\n", *llmModel, *anomalyThreshold)
		fmt.Printf("   ⚙️ Session Key: IP|Service, Idle TTL: %v, Hard TTL: %v, Max Sessions: %d\n\n", *idleTTL, *hardTTL, *maxSessions)
	}

	report := FinalReport{
		Timestamp:         time.Now().Format(time.RFC3339),
		RuleBasedAlerts:   make([]detector.Result, 0),
		LLMICLEvaluations: make([]llm.ICLResult, 0),
	}

	totalLogs := 0
	promptCount := 0

	processLogLine := func(line string) {
		totalLogs++
		ev, err := normalizer.ParseLine(line)
		if err != nil {
			return
		}

		ruleTriggered := false

		// A) Rule-Based Detection
		if r, ok := bruteForceDetector.Process(ev); ok {
			fmt.Printf("⚠️  [RULE DETECTED] %s\n", r.Message)
			report.RuleBasedAlerts = append(report.RuleBasedAlerts, r)
			ruleTriggered = true
		}
		if r, ok := sshBruteForceDetector.Process(ev); ok {
			fmt.Printf("⚠️  [RULE DETECTED] %s\n", r.Message)
			report.RuleBasedAlerts = append(report.RuleBasedAlerts, r)
			ruleTriggered = true
		}
		if r, ok := webEnumDetector.Process(ev); ok {
			fmt.Printf("⚠️  [RULE DETECTED] %s\n", r.Message)
			report.RuleBasedAlerts = append(report.RuleBasedAlerts, r)
			ruleTriggered = true
		}

		// B) Session Context Aggregation & Smart LLM Triggering
		if *enableLLM {
			session := sessionManager.ProcessEvent(ev, ev.TS)
			shouldEval, stats, fingerprint := anomalyEvaluator.ShouldEvaluate(session, ruleTriggered, ev.TS)

			if shouldEval {
				behaviorCtx := session.BuildContext()
				promptInput := llm.PromptInput{
					CorrelationKey:  session.CorrelationKey(),
					Service:         session.Service,
					SourceIP:        session.IP,
					TotalEvents:     len(session.Events),
					Stats:           stats,
					BehaviorContext: behaviorCtx,
				}
				promptCount++

				if *printPrompt && promptCount == 1 {
					generator := llm.NewPromptGenerator()
					fullPrompt := generator.GeneratePromptWithInput(promptInput)
					fmt.Println("==================== [GENERATED LLM PROMPT (PROTOTYPE VERIFICATION)] ====================")
					fmt.Println(fullPrompt)
					fmt.Println("=========================================================================================")
				}

				iclResult, err := iclDetector.EvaluateContextWithInput(promptInput)
				if err == nil {
					report.LLMICLEvaluations = append(report.LLMICLEvaluations, iclResult)

					if iclResult.Result.IsAttack {
						techID := "TXXXX"
						severity := "high"
						techSummary := "Multiple"
						if len(iclResult.Result.Findings) > 0 {
							techID = iclResult.Result.Findings[0].TechniqueID
							severity = iclResult.Result.Findings[0].Severity
							techSummary = fmt.Sprintf("%s (%s)", techID, iclResult.Result.Findings[0].AttackName)
						}

						// Check Stage 2 Alert Cooldown
						if anomalyEvaluator.ShouldAlert(session.CorrelationKey(), techID, severity, ev.TS) {
							fmt.Printf("\n🤖 [LLM ICL ALERT] Key: %s | Engine: %s (Status: %s) | Anomaly Score: %d/32\n", session.CorrelationKey(), iclResult.Engine, iclResult.EvaluationStatus, stats.TotalScore)
							fmt.Printf("   🎯 Technique: %s | Severity: %s\n", techSummary, severity)
							if len(iclResult.Result.Findings) > 0 {
								fmt.Printf("   💡 Reasoning: %s\n", iclResult.Result.Findings[0].Reasoning)
							}
							fmt.Printf("   ⚙️  Model: %s (Fingerprint: %s)\n\n", iclResult.ModelUsed, fingerprint)
						}
					} else {
						fmt.Printf("🟢 [LLM ICL NORMAL] Key: %s | Engine: %s | Anomaly Score: %d/32\n", session.CorrelationKey(), iclResult.Engine, stats.TotalScore)
					}
				}
			}
		}
	}

	if *watchMode {
		fmt.Printf("📡 [Real-Time Watcher] Tailing %d log files in real-time (Press Ctrl+C to stop)...\n", len(files))
		logChan := make(chan string, 1000)
		stopChan := make(chan struct{})

		for _, file := range files {
			f := file
			go func() {
				_ = watcher.TailFile(f, logChan, stopChan)
			}()
		}

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		for {
			select {
			case line := <-logChan:
				processLogLine(line)
			case <-sigChan:
				fmt.Println("\n🛑 Stopping real-time watcher...")
				close(stopChan)
				goto FINALIZE
			}
		}
	} else {
		// Batch processing mode
		for _, file := range files {
			fmt.Printf("🔍 === Analyzing Log File: %s ===\n", file)
			fp, err := os.Open(file)
			if err != nil {
				log.Fatal(err)
			}
			scanner := bufio.NewScanner(fp)
			for scanner.Scan() {
				processLogLine(scanner.Text())
			}
			_ = fp.Close()
		}
	}

FINALIZE:
	report.TotalLogsAnalyzed = totalLogs
	if sessionManager != nil {
		report.ActiveSessions = sessionManager.ActiveSessionsCount()
	}

	// Save JSON report
	reportData, err := json.MarshalIndent(report, "", "  ")
	if err == nil {
		_ = os.WriteFile(*reportFile, reportData, 0644)
		fmt.Printf("\n📊 Analysis complete. Total logs analyzed: %d. Report saved to %s\n", totalLogs, *reportFile)
	}
}
