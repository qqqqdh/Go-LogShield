package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"go-logshield/internal/benchmark"
	"go-logshield/internal/detector/llm"
)

func main() {
	ollamaURL := flag.String("ollama-url", "http://localhost:11434", "Ollama API Endpoint URL")
	llmModel := flag.String("llm-model", "llama3.1:8b", "LLM Model Name for Evaluation")
	reportPath := flag.String("output", "benchmark_report.json", "Output JSON report path")
	flag.Parse()

	fmt.Printf("🚀 [LogShield Benchmark] Running In-Context Learning Evaluation (Model: %s)...\n", *llmModel)

	// 1. Prepare Ground-Truth Test Dataset (Normal & Attack Scenarios)
	dataset := prepareDataset()

	// 2. Initialize LLM ICL Detector
	detector := llm.NewICLDetector(llm.ICLDetectorConfig{
		OllamaURL: *ollamaURL,
		ModelName: *llmModel,
	})

	predictions := make([]bool, len(dataset))
	groundTruths := make([]bool, len(dataset))

	fmt.Println("\n🔍 Evaluating dataset behavior contexts...")

	for i, sample := range dataset {
		groundTruths[i] = sample.IsAttackGround

		result, err := detector.EvaluateContext(sample.BehaviorContext)
		if err != nil {
			log.Printf("Sample %s evaluation error: %v", sample.ID, err)
			continue
		}

		predictions[i] = result.Result.IsAttack

		statusStr := "NORMAL"
		if result.Result.IsAttack {
			techID := "TXXXX"
			if len(result.Result.Findings) > 0 {
				techID = result.Result.Findings[0].TechniqueID
			}
			statusStr = fmt.Sprintf("ATTACK (%s)", techID)
		}

		matchStr := "✅ MATCH"
		if result.Result.IsAttack != sample.IsAttackGround {
			matchStr = "❌ MISMATCH"
		}

		fmt.Printf("[%s] Ground Truth: %t | Prediction: %s | %s\n", sample.ID, sample.IsAttackGround, statusStr, matchStr)
		if result.Result.IsAttack {
			reason := "Attack detected"
			if len(result.Result.Findings) > 0 {
				reason = result.Result.Findings[0].Reasoning
			}
			fmt.Printf("   💡 LLM Reasoning: %s\n", reason)
		}
	}

	// 3. Compute Quantitative Metrics
	evaluator := benchmark.NewEvaluator()
	metrics := evaluator.Compute(predictions, groundTruths)

	// 4. Print Summary to stdout
	metrics.PrintSummary()

	// 5. Save Report to JSON
	reportData, err := json.MarshalIndent(metrics, "", "  ")
	if err == nil {
		_ = os.WriteFile(*reportPath, reportData, 0644)
		fmt.Printf("📄 Benchmark metric report saved to '%s'\n", *reportPath)
	}
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
