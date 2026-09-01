package llm

import (
	"strings"
	"testing"
)

func TestSanitizeLogField(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "Removes newlines and control chars",
			input:    "admin\nuser\r\x07name",
			maxLen:   100,
			expected: "admin user name",
		},
		{
			name:     "Escapes behavior_context XML tags",
			input:    "foo <behavior_context> bar </behavior_context> baz",
			maxLen:   100,
			expected: "foo &lt;behavior_context&gt; bar &lt;/behavior_context&gt; baz",
		},
		{
			name:     "Truncates long path",
			input:    "/very/long/path/that/exceeds/the/specified/maximum/length/limit/and/should/be/truncated/accordingly/to/prevent/prompt/overflow",
			maxLen:   30,
			expected: "/very/long/path/that/exceeds/t...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeLogField(tt.input, tt.maxLen)
			if got != tt.expected {
				t.Errorf("SanitizeLogField() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGeneratePrompt(t *testing.T) {
	gen := NewPromptGenerator()
	ctx := "(1) At 14:00:01, IP 192.168.1.50 performed service=ssh action=login status=failed user=root"
	prompt := gen.GeneratePrompt(ctx)

	if !strings.Contains(prompt, "=== TRUSTED ANALYSIS POLICY ===") {
		t.Errorf("Prompt missing TRUSTED ANALYSIS POLICY header")
	}
	if !strings.Contains(prompt, "=== UNTRUSTED LOG DATA POLICY ===") {
		t.Errorf("Prompt missing UNTRUSTED LOG DATA POLICY header")
	}
	if !strings.Contains(prompt, "<behavior_context>") || !strings.Contains(prompt, "</behavior_context>") {
		t.Errorf("Prompt missing XML behavior_context fencing")
	}
}

func TestGeneratePromptWithInput_ComputedFeatures(t *testing.T) {
	gen := NewPromptGenerator()
	input := PromptInput{
		CorrelationKey: "192.168.1.50|ssh|epoch-1",
		Service:        "ssh",
		SourceIP:       "192.168.1.50",
		TotalEvents:    5,
		Stats: AnomalyStats{
			FailedLoginCount:  4,
			DistinctUserCount: 3,
			TotalScore:        13,
		},
		BehaviorContext: "(1) At 14:00:01, IP 192.168.1.50 performed service=ssh action=login status=failed user=root",
	}

	prompt := gen.GeneratePromptWithInput(input)

	if !strings.Contains(prompt, "=== COMPUTED STATISTICAL FEATURES ===") {
		t.Errorf("Prompt missing COMPUTED STATISTICAL FEATURES header")
	}
	if !strings.Contains(prompt, "Correlation Key: 192.168.1.50|ssh|epoch-1") {
		t.Errorf("Prompt missing Correlation Key feature line")
	}
	if !strings.Contains(prompt, "Pre-computed Anomaly Score: 13 / 32") {
		t.Errorf("Prompt missing Anomaly Score feature line")
	}
	if !strings.Contains(prompt, "Example 2 (Borderline / Suspicious - Single Typo)") {
		t.Errorf("Prompt missing 3-tier Few-Shot Borderline example")
	}
}
