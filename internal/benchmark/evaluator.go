package benchmark

import (
	"fmt"
	"math"
	"time"
)

type TechMetric struct {
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1Score   float64 `json:"f1_score"`
}

// MetricResult holds comprehensive quantitative evaluation scores.
type MetricResult struct {
	ModeName         string                `json:"mode_name"`
	TotalSamples     int                   `json:"total_samples"`
	TP               int                   `json:"true_positive"`
	FP               int                   `json:"false_positive"`
	TN               int                   `json:"true_negative"`
	FN               int                   `json:"false_negative"`
	Accuracy         float64               `json:"accuracy"`
	Precision        float64               `json:"precision"`
	Recall           float64               `json:"recall"`
	F1Score          float64               `json:"f1_score"`
	FPR              float64               `json:"false_positive_rate"`
	AvgLatencyMs     float64               `json:"avg_latency_ms"`
	LLMCallCount     int                   `json:"llm_call_count"`
	DegradedRatio    float64               `json:"degraded_ratio"`
	InvalidRatio     float64               `json:"invalid_ratio"`
	TechniqueMetrics map[string]TechMetric `json:"technique_metrics,omitempty"`
}

// PredictionDetail holds details for a single sample evaluation in a benchmark run.
type PredictionDetail struct {
	SampleID       string
	IsAttack       bool
	TechniqueID    string
	IsDegraded     bool
	IsInvalid      bool
	Latency        time.Duration
	ExecutedLLM    bool
}

// Sample holds a behavior context test case with its ground truth label.
type Sample struct {
	ID              string   `json:"id"`
	BehaviorContext string   `json:"behavior_context"`
	IsAttackGround  bool     `json:"is_attack_ground"`
	GroundTechnique string   `json:"ground_technique"`
	Events          []string `json:"events,omitempty"`
}

type MultiModeBenchmarkReport struct {
	Timestamp      string       `json:"timestamp"`
	RuleOnly       MetricResult `json:"rule_only"`
	FallbackOnly   MetricResult `json:"fallback_only"`
	LLMOnly        MetricResult `json:"llm_only"`
	HybridPipeline MetricResult `json:"hybrid_pipeline"`
}

type Evaluator struct{}

func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

func (e *Evaluator) ComputeDetailed(modeName string, predictions []PredictionDetail, dataset []Sample) MetricResult {
	tp, fp, tn, fn := 0, 0, 0, 0
	llmCalls := 0
	degradedCount := 0
	invalidCount := 0
	var totalLatency time.Duration

	techMap := make(map[string]*TechMetric)

	for i := 0; i < len(predictions); i++ {
		p := predictions[i]
		truth := dataset[i].IsAttackGround
		groundTech := dataset[i].GroundTechnique

		totalLatency += p.Latency
		if p.ExecutedLLM {
			llmCalls++
		}
		if p.IsDegraded {
			degradedCount++
		}
		if p.IsInvalid {
			invalidCount++
		}

		if p.IsAttack && truth {
			tp++
		} else if p.IsAttack && !truth {
			fp++
		} else if !p.IsAttack && !truth {
			tn++
		} else if !p.IsAttack && truth {
			fn++
		}

		// Per-technique metrics
		if groundTech != "" && groundTech != "None" {
			if _, exists := techMap[groundTech]; !exists {
				techMap[groundTech] = &TechMetric{}
			}
			if p.IsAttack && p.TechniqueID == groundTech {
				techMap[groundTech].TP++
			} else if p.IsAttack && p.TechniqueID != groundTech {
				techMap[groundTech].FP++
			} else if !p.IsAttack {
				techMap[groundTech].FN++
			}
		}
	}

	total := len(predictions)
	acc := 0.0
	if total > 0 {
		acc = float64(tp+tn) / float64(total)
	}

	prec := 0.0
	if (tp + fp) > 0 {
		prec = float64(tp) / float64(tp+fp)
	}

	rec := 0.0
	if (tp + fn) > 0 {
		rec = float64(tp) / float64(tp+fn)
	}

	f1 := 0.0
	if (prec + rec) > 0 {
		f1 = 2 * (prec * rec) / (prec + rec)
	}

	fpr := 0.0
	if (fp + tn) > 0 {
		fpr = float64(fp) / float64(fp+tn)
	}

	avgLatMs := 0.0
	if total > 0 {
		avgLatMs = float64(totalLatency.Milliseconds()) / float64(total)
	}

	degradedRatio := 0.0
	if total > 0 {
		degradedRatio = float64(degradedCount) / float64(total)
	}

	invalidRatio := 0.0
	if total > 0 {
		invalidRatio = float64(invalidCount) / float64(total)
	}

	// Finalize technique metrics
	finalTechMetrics := make(map[string]TechMetric)
	for tech, tm := range techMap {
		tPrec := 0.0
		if (tm.TP + tm.FP) > 0 {
			tPrec = float64(tm.TP) / float64(tm.TP+tm.FP)
		}
		tRec := 0.0
		if (tm.TP + tm.FN) > 0 {
			tRec = float64(tm.TP) / float64(tm.TP+tm.FN)
		}
		tF1 := 0.0
		if (tPrec + tRec) > 0 {
			tF1 = 2 * (tPrec * tRec) / (tPrec + tRec)
		}
		finalTechMetrics[tech] = TechMetric{
			TP:        tm.TP,
			FP:        tm.FP,
			FN:        tm.FN,
			Precision: roundFloat(tPrec, 4),
			Recall:    roundFloat(tRec, 4),
			F1Score:   roundFloat(tF1, 4),
		}
	}

	return MetricResult{
		ModeName:         modeName,
		TotalSamples:     total,
		TP:               tp,
		FP:               fp,
		TN:               tn,
		FN:               fn,
		Accuracy:         roundFloat(acc, 4),
		Precision:        roundFloat(prec, 4),
		Recall:           roundFloat(rec, 4),
		F1Score:          roundFloat(f1, 4),
		FPR:              roundFloat(fpr, 4),
		AvgLatencyMs:     roundFloat(avgLatMs, 2),
		LLMCallCount:     llmCalls,
		DegradedRatio:    roundFloat(degradedRatio, 4),
		InvalidRatio:     roundFloat(invalidRatio, 4),
		TechniqueMetrics: finalTechMetrics,
	}
}

func (e *Evaluator) Compute(predictions []bool, groundTruths []bool) MetricResult {
	details := make([]PredictionDetail, len(predictions))
	dataset := make([]Sample, len(predictions))
	for i := 0; i < len(predictions); i++ {
		details[i] = PredictionDetail{
			IsAttack: predictions[i],
		}
		dataset[i] = Sample{
			IsAttackGround: groundTruths[i],
		}
	}
	return e.ComputeDetailed("Legacy", details, dataset)
}

func roundFloat(val float64, precision int) float64 {
	ratio := math.Pow(10, float64(precision))
	return math.Round(val*ratio) / ratio
}

func (r MultiModeBenchmarkReport) PrintComparisonSummary() {
	fmt.Println("\n📊 ==================== LOGSHIELD 4-MODE BENCHMARK EVALUATION ====================")
	fmt.Printf("%-18s | %-8s | %-8s | %-8s | %-8s | %-10s | %-10s\n", "Mode", "Accuracy", "Precision", "Recall", "F1-Score", "LLM Calls", "Avg Latency")
	fmt.Println("--------------------------------------------------------------------------------------------------")
	printModeRow(r.RuleOnly)
	printModeRow(r.FallbackOnly)
	printModeRow(r.LLMOnly)
	printModeRow(r.HybridPipeline)
	fmt.Println("================================================================================------------------")
}

func printModeRow(m MetricResult) {
	fmt.Printf("%-18s | %-8.4f | %-8.4f | %-8.4f | %-8.4f | %-10d | %-8.2fms\n",
		m.ModeName, m.Accuracy, m.Precision, m.Recall, m.F1Score, m.LLMCallCount, m.AvgLatencyMs)
}

func (m MetricResult) PrintSummary() {
	fmt.Printf("\n📊 ==================== [%s] BENCHMARK REPORT ====================\n", m.ModeName)
	fmt.Printf("Total Evaluation Samples : %d\n", m.TotalSamples)
	fmt.Printf("Confusion Matrix         : TP=%d, FP=%d, TN=%d, FN=%d\n", m.TP, m.FP, m.TN, m.FN)
	fmt.Printf("Accuracy                 : %.4f (%.2f%%)\n", m.Accuracy, m.Accuracy*100)
	fmt.Printf("Precision                : %.4f (%.2f%%)\n", m.Precision, m.Precision*100)
	fmt.Printf("Recall                   : %.4f (%.2f%%)\n", m.Recall, m.Recall*100)
	fmt.Printf("F1-Score                 : %.4f (%.2f%%)\n", m.F1Score, m.F1Score*100)
	fmt.Printf("False Positive Rate (FPR): %.4f (%.2f%%)\n", m.FPR, m.FPR*100)
	fmt.Printf("LLM Call Count           : %d\n", m.LLMCallCount)
	fmt.Printf("Average Latency          : %.2f ms\n", m.AvgLatencyMs)
	fmt.Printf("Degraded / Invalid Ratio : Degraded=%.2f%%, Invalid=%.2f%%\n", m.DegradedRatio*100, m.InvalidRatio*100)
	fmt.Println("=====================================================================================")
}
