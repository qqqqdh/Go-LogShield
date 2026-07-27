package llm

import (
	"bytes"
	"encoding/json"
	"fmt"

	"net/http"
	"strings"
	"time"
)

type ICLDetectorConfig struct {
	OllamaURL  string        // e.g., "http://localhost:11434"
	ModelName  string        // e.g., "llama3.1:8b" or "llama3.1"
	Timeout    time.Duration // API call timeout
	EnableMock bool          // Fallback if Ollama is offline
}

type ICLDetector struct {
	config    ICLDetectorConfig
	generator *PromptGenerator
	client    *http.Client
}

type ICLResult struct {
	IsAttack    bool   `json:"is_attack"`
	TechniqueID string `json:"technique_id"`
	AttackName  string `json:"attack_name"`
	Reasoning   string `json:"reasoning"`
	ModelUsed   string `json:"model_used"`
	Prompt      string `json:"prompt_used,omitempty"`
}

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

func NewICLDetector(config ICLDetectorConfig) *ICLDetector {
	if config.OllamaURL == "" {
		config.OllamaURL = "http://localhost:11434"
	}
	if config.ModelName == "" {
		config.ModelName = "llama3.1:8b"
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}

	return &ICLDetector{
		config:    config,
		generator: NewPromptGenerator(),
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// EvaluateContext takes a natural language behavior context, generates an ICL prompt,
// sends it to the LLM (Ollama LLaMA 3.1 8B), and returns the interpreted intrusion detection result.
func (d *ICLDetector) EvaluateContext(behaviorContext string) (ICLResult, error) {
	prompt := d.generator.GeneratePrompt(behaviorContext)

	// Attempt real Ollama HTTP call
	reqBody := ollamaRequest{
		Model:  d.config.ModelName,
		Prompt: prompt,
		Stream: false,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return d.fallbackEvaluate(behaviorContext, err)
	}

	apiURL := fmt.Sprintf("%s/api/generate", strings.TrimRight(d.config.OllamaURL, "/"))
	resp, err := d.client.Post(apiURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		// Fallback to local heuristic ICL simulator if Ollama service is unavailable
		return d.fallbackEvaluate(behaviorContext, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return d.fallbackEvaluate(behaviorContext, fmt.Errorf("Ollama API returned status %d", resp.StatusCode))
	}

	var ollamaResp ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return d.fallbackEvaluate(behaviorContext, err)
	}

	// Parse JSON output from LLM response text
	rawJSON := cleanJSONResponse(ollamaResp.Response)
	var result ICLResult
	if err := json.Unmarshal([]byte(rawJSON), &result); err != nil {
		// If LLM returned free text instead of strict JSON, populate reasoning
		result.IsAttack = strings.Contains(strings.ToLower(ollamaResp.Response), "true") || strings.Contains(strings.ToLower(ollamaResp.Response), "attack")
		result.AttackName = "LLM In-Context Detection"
		result.Reasoning = strings.TrimSpace(ollamaResp.Response)
	}
	result.ModelUsed = d.config.ModelName
	result.Prompt = prompt

	return result, nil
}

// Clean JSON response from potential markdown fence ```json ... ```
func cleanJSONResponse(respText string) string {
	respText = strings.TrimSpace(respText)
	if strings.HasPrefix(respText, "```") {
		lines := strings.Split(respText, "\n")
		if len(lines) >= 2 {
			if strings.HasPrefix(lines[0], "```") {
				lines = lines[1:]
			}
			if strings.HasPrefix(lines[len(lines)-1], "```") {
				lines = lines[:len(lines)-1]
			}
			respText = strings.Join(lines, "\n")
		}
	}
	return strings.TrimSpace(respText)
}

// Fallback heuristic evaluator for zero-dependency local testing when Ollama server is offline.
func (d *ICLDetector) fallbackEvaluate(behaviorContext string, cause error) (ICLResult, error) {
	ctxLower := strings.ToLower(behaviorContext)

	res := ICLResult{
		ModelUsed: fmt.Sprintf("%s (ICL Fallback Engine: %v)", d.config.ModelName, cause),
	}

	// Simulated In-Context Rule matching for baseline demonstration
	failedCount := strings.Count(ctxLower, "status=failed") + strings.Count(ctxLower, "status=401")
	notfoundCount := strings.Count(ctxLower, "status=404") + strings.Count(ctxLower, "path=/.env") + strings.Count(ctxLower, "path=/admin")

	if failedCount >= 3 {
		res.IsAttack = true
		res.TechniqueID = "T1110"
		res.AttackName = "Brute Force / Credential Access"
		res.Reasoning = fmt.Sprintf("[In-Context Evaluation] Multiple authentication failures (%d events) observed in sliding window context, matching MITRE T1110.", failedCount)
	} else if notfoundCount >= 2 {
		res.IsAttack = true
		res.TechniqueID = "T1595"
		res.AttackName = "Active Scanning / Web Enumeration"
		res.Reasoning = fmt.Sprintf("[In-Context Evaluation] Sensitive path probing or repeated 404 errors (%d events) detected in sliding window context, matching MITRE T1595.", notfoundCount)
	} else {
		res.IsAttack = false
		res.TechniqueID = "None"
		res.AttackName = "Normal"
		res.Reasoning = "[In-Context Evaluation] Behavior context consists of legitimate status codes and standard service requests."
	}

	return res, nil
}
