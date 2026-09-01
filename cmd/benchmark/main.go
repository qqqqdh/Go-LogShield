package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"go-logshield/internal/benchmark"
	"go-logshield/internal/detector/llm"
)

func main() {
	ollamaURL := flag.String("ollama-url", "http://localhost:11434", "Ollama API Endpoint URL")
	llmModel := flag.String("llm-model", "llama3.1:8b", "LLM Model Name for Evaluation")
	reportPath := flag.String("output", "benchmark_report.json", "Output JSON report path")
	flag.Parse()

	fmt.Printf("🚀 [LogShield Benchmark] Running 4-Mode Independent Evaluation (Model: %s)...\n", *llmModel)

	dataset := prepareDataset()
	evaluator := benchmark.NewEvaluator()

	detector := llm.NewICLDetector(llm.ICLDetectorConfig{
		OllamaURL: *ollamaURL,
		ModelName: *llmModel,
		Timeout:   5 * time.Second,
	})

	// 1. Mode 1: Rule-Only Baseline
	fmt.Println("\n🔍 [Mode 1/4] Running Rule-Only Detector Evaluation...")
	ruleDetails := evaluateRuleOnly(dataset)
	ruleResult := evaluator.ComputeDetailed("Rule-Only Baseline", ruleDetails, dataset)

	// 2. Mode 2: Fallback-Only Heuristic Baseline
	fmt.Println("🔍 [Mode 2/4] Running Fallback-Only Heuristic Evaluation...")
	fallbackDetails := evaluateFallbackOnly(dataset, detector)
	fallbackResult := evaluator.ComputeDetailed("Fallback-Only Baseline", fallbackDetails, dataset)

	// 3. Mode 3: LLM-Only Pure Evaluation (Without Anomaly Pre-filter)
	fmt.Println("🔍 [Mode 3/4] Running LLM-Only Pure Context Evaluation...")
	llmDetails := evaluateLLMOnly(dataset, detector)
	llmResult := evaluator.ComputeDetailed("LLM-Only (No Filter)", llmDetails, dataset)

	// 4. Mode 4: Hybrid Pipeline (Anomaly Filter + LLM 2nd Stage)
	fmt.Println("🔍 [Mode 4/4] Running Hybrid Pipeline (Rule/Anomaly Filter + LLM)...")
	hybridDetails := evaluateHybridPipeline(dataset, detector)
	hybridResult := evaluator.ComputeDetailed("Hybrid Pipeline (Production)", hybridDetails, dataset)

	// Create Multi-Mode Benchmark Report
	multiReport := benchmark.MultiModeBenchmarkReport{
		Timestamp:      time.Now().Format(time.RFC3339),
		RuleOnly:       ruleResult,
		FallbackOnly:   fallbackResult,
		LLMOnly:        llmResult,
		HybridPipeline: hybridResult,
	}

	// Print comparison summary
	multiReport.PrintComparisonSummary()

	// Print detailed summary for Hybrid Pipeline
	hybridResult.PrintSummary()

	// Save JSON report
	reportData, err := json.MarshalIndent(multiReport, "", "  ")
	if err == nil {
		_ = os.WriteFile(*reportPath, reportData, 0644)
		fmt.Printf("\n📄 Multi-mode benchmark metric report saved to '%s'\n", *reportPath)
	}
}

func evaluateRuleOnly(dataset []benchmark.Sample) []benchmark.PredictionDetail {
	details := make([]benchmark.PredictionDetail, len(dataset))
	for i, sample := range dataset {
		start := time.Now()
		ctxLower := strings.ToLower(sample.BehaviorContext)
		failedCount := strings.Count(ctxLower, "status=failed") + strings.Count(ctxLower, "status=fail") + strings.Count(ctxLower, "status=401")
		notfoundCount := strings.Count(ctxLower, "status=404")

		isAttack := false
		techID := "None"
		if failedCount >= 4 {
			isAttack = true
			techID = "T1110"
		} else if notfoundCount >= 3 {
			isAttack = true
			techID = "T1595"
		}

		details[i] = benchmark.PredictionDetail{
			SampleID:    sample.ID,
			IsAttack:    isAttack,
			TechniqueID: techID,
			Latency:     time.Since(start),
			ExecutedLLM: false,
		}
	}
	return details
}

func evaluateFallbackOnly(dataset []benchmark.Sample, detector *llm.ICLDetector) []benchmark.PredictionDetail {
	details := make([]benchmark.PredictionDetail, len(dataset))
	for i, sample := range dataset {
		start := time.Now()
		// Execute with network failure simulation or fallback check
		ctxLower := strings.ToLower(sample.BehaviorContext)
		failedCount := strings.Count(ctxLower, "status=failed") + strings.Count(ctxLower, "status=fail") + strings.Count(ctxLower, "status=401")
		notfoundCount := strings.Count(ctxLower, "status=404") + strings.Count(ctxLower, "path=/.env")

		isAttack := false
		techID := "None"
		if failedCount >= 3 {
			isAttack = true
			techID = "T1110"
		} else if notfoundCount >= 2 {
			isAttack = true
			techID = "T1595"
		}

		details[i] = benchmark.PredictionDetail{
			SampleID:    sample.ID,
			IsAttack:    isAttack,
			TechniqueID: techID,
			IsDegraded:  true,
			Latency:     time.Since(start),
			ExecutedLLM: false,
		}
	}
	return details
}

func evaluateLLMOnly(dataset []benchmark.Sample, detector *llm.ICLDetector) []benchmark.PredictionDetail {
	details := make([]benchmark.PredictionDetail, len(dataset))
	for i, sample := range dataset {
		start := time.Now()
		result, err := detector.EvaluateContext(sample.BehaviorContext)
		lat := time.Since(start)

		if err != nil {
			log.Printf("Sample %s evaluation error: %v", sample.ID, err)
		}

		techID := "None"
		if len(result.Result.Findings) > 0 {
			techID = result.Result.Findings[0].TechniqueID
		}

		details[i] = benchmark.PredictionDetail{
			SampleID:    sample.ID,
			IsAttack:    result.Result.IsAttack,
			TechniqueID: techID,
			IsDegraded:  result.DegradedMode,
			IsInvalid:   result.Engine == llm.EngineInvalid,
			Latency:     lat,
			ExecutedLLM: true,
		}
	}
	return details
}

func evaluateHybridPipeline(dataset []benchmark.Sample, detector *llm.ICLDetector) []benchmark.PredictionDetail {
	details := make([]benchmark.PredictionDetail, len(dataset))
	for i, sample := range dataset {
		start := time.Now()

		// 1. Calculate Anomaly Score
		// Parse dummy events from behavior context string for scoring
		ctxLower := strings.ToLower(sample.BehaviorContext)
		failedCount := strings.Count(ctxLower, "status=failed") + strings.Count(ctxLower, "status=fail")
		notfoundCount := strings.Count(ctxLower, "status=404")
		sensitiveCount := strings.Count(ctxLower, "path=/.env") + strings.Count(ctxLower, "path=/admin")

		score := (failedCount * 2) + (notfoundCount * 1) + (sensitiveCount * 3)

		// 2. Only invoke LLM if score >= threshold (7)
		isAttack := false
		techID := "None"
		executedLLM := false
		isDegraded := false
		isInvalid := false

		if score >= 7 {
			executedLLM = true
			result, err := detector.EvaluateContext(sample.BehaviorContext)
			if err == nil {
				isAttack = result.Result.IsAttack
				if len(result.Result.Findings) > 0 {
					techID = result.Result.Findings[0].TechniqueID
				}
				isDegraded = result.DegradedMode
				isInvalid = result.Engine == llm.EngineInvalid
			}
		}

		details[i] = benchmark.PredictionDetail{
			SampleID:    sample.ID,
			IsAttack:    isAttack,
			TechniqueID: techID,
			IsDegraded:  isDegraded,
			IsInvalid:   isInvalid,
			Latency:     time.Since(start),
			ExecutedLLM: executedLLM,
		}
	}
	return details
}

func prepareDataset() []benchmark.Sample {
	return []benchmark.Sample{
		// Normal Samples
		{
			ID:              "N1",
			IsAttackGround:  false,
			GroundTechnique: "None",
			BehaviorContext: "(1) At 10:00:01, IP 10.0.0.1 performed service=web action=get status=200 path=/index.html\n(2) At 10:00:05, IP 10.0.0.1 performed service=web action=get status=200 path=/style.css\n(3) At 10:00:10, IP 10.0.0.1 performed service=web action=get status=200 path=/favicon.ico",
		},
		{
			ID:              "N2",
			IsAttackGround:  false,
			GroundTechnique: "None",
			BehaviorContext: "(1) At 11:00:00, IP 192.168.1.15 performed service=auth action=login status=success user=bob path=\n(2) At 11:05:00, IP 192.168.1.15 performed service=web action=get status=200 path=/dashboard",
		},
		{
			ID:              "N3",
			IsAttackGround:  false,
			GroundTechnique: "None",
			BehaviorContext: "(1) At 12:00:00, IP 10.0.0.50 performed service=ssh action=login status=success user=ubuntu path=",
		},

		// Attack Samples: Brute Force (T1110)
		{
			ID:              "A1_T1110",
			IsAttackGround:  true,
			GroundTechnique: "T1110",
			BehaviorContext: "(1) At 12:00:01, IP 203.0.113.10 performed service=auth action=login status=FAIL user=alice path=\n(2) At 12:00:02, IP 203.0.113.10 performed service=auth action=login status=FAIL user=alice path=\n(3) At 12:00:03, IP 203.0.113.10 performed service=auth action=login status=FAIL user=admin path=\n(4) At 12:00:04, IP 203.0.113.10 performed service=auth action=login status=FAIL user=root path=\n(5) At 12:00:05, IP 203.0.113.10 performed service=auth action=login status=FAIL user=user path=",
		},
		{
			ID:              "A2_T1110",
			IsAttackGround:  true,
			GroundTechnique: "T1110",
			BehaviorContext: "(1) At 14:00:01, IP 198.51.100.23 performed service=ssh action=login status=failed user=root path=\n(2) At 14:00:02, IP 198.51.100.23 performed service=ssh action=login status=failed user=root path=\n(3) At 14:00:03, IP 198.51.100.23 performed service=ssh action=login status=failed user=root path=\n(4) At 14:00:04, IP 198.51.100.23 performed service=ssh action=login status=failed user=root path=",
		},

		// Attack Samples: Web Enumeration / Scanning (T1595)
		{
			ID:              "A3_T1595",
			IsAttackGround:  true,
			GroundTechnique: "T1595",
			BehaviorContext: "(1) At 15:00:01, IP 198.51.100.45 performed service=web action=get status=404 path=/.env\n(2) At 15:00:02, IP 198.51.100.45 performed service=web action=get status=404 path=/admin\n(3) At 15:00:03, IP 198.51.100.45 performed service=web action=get status=404 path=/config.json\n(4) At 15:00:04, IP 198.51.100.45 performed service=web action=get status=404 path=/backup.sql",
		},
		{
			ID:              "A4_T1595",
			IsAttackGround:  true,
			GroundTechnique: "T1595",
			BehaviorContext: "(1) At 16:00:01, IP 172.16.0.99 performed service=web action=get status=404 path=/wp-login.php\n(2) At 16:00:02, IP 172.16.0.99 performed service=web action=get status=404 path=/phpmyadmin\n(3) At 16:00:03, IP 172.16.0.99 performed service=web action=get status=404 path=/.git/config",
		},
	}
}
