package benchmark

import (
	"fmt"
	"math"
)

// MetricResult holds the quantitative evaluation scores.
type MetricResult struct {
	TotalSamples int     `json:"total_samples"`
	TP           int     `json:"true_positive"`
	FP           int     `json:"false_positive"`
	TN           int     `json:"true_negative"`
	FN           int     `json:"false_negative"`
	Accuracy     float64 `json:"accuracy"`
	Precision    float64 `json:"precision"`
	Recall       float64 `json:"recall"`
	F1Score      float64 `json:"f1_score"`
}

// Sample holds a behavior context test case with its ground truth label.
type Sample struct {
	ID              string
	BehaviorContext string
	IsAttackGround  bool
	GroundTechnique string
}

// Evaluator computes Precision, Recall, Accuracy, F1-Score, and Confusion Matrix.
type Evaluator struct{}

func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

func (e *Evaluator) Compute(predictions []bool, groundTruths []bool) MetricResult {
	tp, fp, tn, fn := 0, 0, 0, 0

	for i := 0; i < len(predictions); i++ {
		pred := predictions[i]
		truth := groundTruths[i]

		if pred && truth {
			tp++
		} else if pred && !truth {
			fp++
		} else if !pred && !truth {
			tn++
		} else if !pred && truth {
			fn++
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

	return MetricResult{
		TotalSamples: total,
		TP:           tp,
		FP:           fp,
		TN:           tn,
		FN:           fn,
		Accuracy:     roundFloat(acc, 4),
		Precision:    roundFloat(prec, 4),
		Recall:       roundFloat(rec, 4),
		F1Score:      roundFloat(f1, 4),
	}
}

func roundFloat(val float64, precision int) float64 {
	ratio := math.Pow(10, float64(precision))
	return math.Round(val*ratio) / ratio
}

func (m MetricResult) PrintSummary() {
	fmt.Println("\n📊 ==================== LLM IN-CONTEXT LEARNING BENCHMARK REPORT ====================")
	fmt.Printf("Total Evaluation Samples: %d\n", m.TotalSamples)
	fmt.Println("-------------------------------------------------------------------------------------")
	fmt.Printf("Confusion Matrix  : TP=%d, FP=%d, TN=%d, FN=%d\n", m.TP, m.FP, m.TN, m.FN)
	fmt.Printf("Accuracy          : %.4f (%.2f%%)\n", m.Accuracy, m.Accuracy*100)
	fmt.Printf("Precision         : %.4f (%.2f%%)\n", m.Precision, m.Precision*100)
	fmt.Printf("Recall            : %.4f (%.2f%%)\n", m.Recall, m.Recall*100)
	fmt.Printf("F1-Score          : %.4f (%.2f%%)\n", m.F1Score, m.F1Score*100)
	fmt.Println("=====================================================================================")
}
