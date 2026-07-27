package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"go-logshield/internal/detector"
	"go-logshield/internal/detector/llm"
	"go-logshield/internal/normalizer"
)

type FinalReport struct {
	Timestamp          string                  `json:"timestamp"`
	RuleBasedAlerts    []detector.Result       `json:"rule_based_alerts"`
	LLMICLEvaluations []llm.ICLResult         `json:"llm_icl_evaluations"`
	TotalLogsAnalyzed  int                     `json:"total_logs_analyzed"`
}

func main() {
	logDir := flag.String("log-dir", "./logs", "Path to log directory containing .log files")
	enableLLM := flag.Bool("llm", true, "Enable LLaMA 3.1 8B In-Context Learning (ICL) Detector")
	ollamaURL := flag.String("ollama-url", "http://localhost:11434", "Ollama API Endpoint URL")
	llmModel := flag.String("llm-model", "llama3.1:8b", "LLM Model Name for In-Context Learning")
	windowSize := flag.Int("window-size", 5, "Sliding window size (event count) for behavior context aggregation")
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

	// 3. Initialize Paper-Based LLM In-Context Learning (ICL) Engine
	var contextBuilder *llm.BehaviorContextBuilder
	var iclDetector *llm.ICLDetector
	if *enableLLM {
		contextBuilder = llm.NewBehaviorContextBuilder(*windowSize)
		iclDetector = llm.NewICLDetector(llm.ICLDetectorConfig{
			OllamaURL: *ollamaURL,
			ModelName: *llmModel,
			Timeout:   5 * time.Second,
		})
		fmt.Printf("🤖 [LogShield] LLM In-Context Learning Engine Initialized (Model: %s, Window: %d events)\n\n", *llmModel, *windowSize)
	}

	report := FinalReport{
		Timestamp:          time.Now().Format(time.RFC3339),
		RuleBasedAlerts:    make([]detector.Result, 0),
		LLMICLEvaluations: make([]llm.ICLResult, 0),
	}

	totalLogs := 0

	// 4. Iterate over log files
	for _, file := range files {
		fmt.Printf("🔍 === Analyzing Log File: %s ===\n", file)

		fp, err := os.Open(file)
		if err != nil {
			log.Fatal(err)
		}

		scanner := bufio.NewScanner(fp)
		for scanner.Scan() {
			line := scanner.Text()
			totalLogs++

			// Normalize log into Event
			ev, err := normalizer.ParseLine(line)
			if err != nil {
				continue
			}

			// A) Rule-Based Intrusion Detection
			if r, ok := bruteForceDetector.Process(ev); ok {
				fmt.Printf("⚠️  [RULE DETECTED] %s\n", r.Message)
				report.RuleBasedAlerts = append(report.RuleBasedAlerts, r)
			}
			if r, ok := sshBruteForceDetector.Process(ev); ok {
				fmt.Printf("⚠️  [RULE DETECTED] %s\n", r.Message)
				report.RuleBasedAlerts = append(report.RuleBasedAlerts, r)
			}
			if r, ok := webEnumDetector.Process(ev); ok {
				fmt.Printf("⚠️  [RULE DETECTED] %s\n", r.Message)
				report.RuleBasedAlerts = append(report.RuleBasedAlerts, r)
			}

			// B) LLM In-Context Learning (ICL) Behavior Context Aggregation
			if *enableLLM {
				contextBuilder.AddEvent(ev)
				if contextBuilder.IsFull() {
					behaviorCtx := contextBuilder.BuildContext()
					iclResult, err := iclDetector.EvaluateContext(behaviorCtx)
					if err == nil {
						report.LLMICLEvaluations = append(report.LLMICLEvaluations, iclResult)
						if iclResult.IsAttack {
							fmt.Printf("\n🤖 [LLM ICL ALERT] MITRE Technique: %s (%s)\n", iclResult.TechniqueID, iclResult.AttackName)
							fmt.Printf("   💡 Reasoning: %s\n", iclResult.Reasoning)
							fmt.Printf("   ⚙️  Model: %s\n\n", iclResult.ModelUsed)
						} else {
							fmt.Printf("🟢 [LLM ICL NORMAL] Behavior context evaluated as legitimate (%s)\n", iclResult.Reasoning)
						}
					}
				}
			}
		}

		// Process remaining events in buffer for LLM
		if *enableLLM && !contextBuilder.IsFull() {
			behaviorCtx := contextBuilder.BuildContext()
			if behaviorCtx != "No behavior recorded." {
				iclResult, err := iclDetector.EvaluateContext(behaviorCtx)
				if err == nil {
					report.LLMICLEvaluations = append(report.LLMICLEvaluations, iclResult)
					if iclResult.IsAttack {
						fmt.Printf("\n🤖 [LLM ICL ALERT - Final Window] MITRE Technique: %s (%s)\n", iclResult.TechniqueID, iclResult.AttackName)
						fmt.Printf("   💡 Reasoning: %s\n\n", iclResult.Reasoning)
					}
				}
			}
		}

		_ = fp.Close()
	}

	report.TotalLogsAnalyzed = totalLogs

	// Save JSON report
	reportData, err := json.MarshalIndent(report, "", "  ")
	if err == nil {
		_ = os.WriteFile(*reportFile, reportData, 0644)
		fmt.Printf("\n📊 Analysis complete. Total logs analyzed: %d. Report saved to %s\n", totalLogs, *reportFile)
	}
}
