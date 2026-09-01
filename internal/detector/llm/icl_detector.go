package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type Engine string

const (
	EngineLLM          Engine = "llm"
	EngineFallbackRule Engine = "fallback_rule"
	EngineInvalid      Engine = "invalid"
)

type EvaluationStatus string

const (
	StatusValid       EvaluationStatus = "valid"
	StatusParseError  EvaluationStatus = "parse_error"
	StatusSchemaError EvaluationStatus = "schema_error"
	StatusTimeout     EvaluationStatus = "timeout"
	StatusUnavailable EvaluationStatus = "unavailable"
)

type Finding struct {
	TechniqueID      string `json:"technique_id"`
	AttackName       string `json:"attack_name"`
	Severity         string `json:"severity"`          // low, medium, high, critical
	EvidenceEventIDs []int  `json:"evidence_event_ids"` // minimal 1 item when attack
	Reasoning        string `json:"reasoning"`
}

type LLMResponsePayload struct {
	IsAttack          bool      `json:"is_attack"`
	Confidence        float64   `json:"confidence"`
	Findings          []Finding `json:"findings"`
	RecommendedAction string    `json:"recommended_action,omitempty"`
}

type ICLResult struct {
	Engine           Engine             `json:"engine"`
	DegradedMode     bool               `json:"degraded_mode"`
	EvaluationStatus EvaluationStatus   `json:"evaluation_status"`
	AttemptCount     int                `json:"attempt_count"`
	ModelUsed        string             `json:"model_used,omitempty"`
	ParseError       string             `json:"parse_error,omitempty"`
	Prompt           string             `json:"prompt_used,omitempty"`
	Result           LLMResponsePayload `json:"result"`
}

// InferenceClient abstracts LLM execution for decoupling (Ollama, OpenAI, etc.).
type InferenceClient interface {
	Generate(ctx context.Context, prompt string) (string, error)
}

type OllamaClientConfig struct {
	OllamaURL string
	ModelName string
	Timeout   time.Duration
}

type OllamaClient struct {
	config OllamaClientConfig
	client *http.Client
}

func NewOllamaClient(config OllamaClientConfig) *OllamaClient {
	if config.OllamaURL == "" {
		config.OllamaURL = "http://localhost:11434"
	}
	if config.ModelName == "" {
		config.ModelName = "llama3.1:8b"
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	return &OllamaClient{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}
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

func (c *OllamaClient) Generate(ctx context.Context, prompt string) (string, error) {
	reqBody := ollamaRequest{
		Model:  c.config.ModelName,
		Prompt: prompt,
		Stream: false,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request error: %w", err)
	}

	apiURL := fmt.Sprintf("%s/api/generate", strings.TrimRight(c.config.OllamaURL, "/"))
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(data))
	if err != nil {
		return "", fmt.Errorf("create request error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama API status %d", resp.StatusCode)
	}

	var ollamaResp ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", fmt.Errorf("decode response error: %w", err)
	}

	return ollamaResp.Response, nil
}

type ICLDetectorConfig struct {
	OllamaURL  string
	ModelName  string
	Timeout    time.Duration
	EnableMock bool
}

type ICLDetector struct {
	config    ICLDetectorConfig
	generator *PromptGenerator
	client    InferenceClient
}

func NewICLDetector(config ICLDetectorConfig) *ICLDetector {
	ollamaClient := NewOllamaClient(OllamaClientConfig{
		OllamaURL: config.OllamaURL,
		ModelName: config.ModelName,
		Timeout:   config.Timeout,
	})
	return &ICLDetector{
		config:    config,
		generator: NewPromptGenerator(),
		client:    ollamaClient,
	}
}

func NewICLDetectorWithClient(config ICLDetectorConfig, client InferenceClient) *ICLDetector {
	return &ICLDetector{
		config:    config,
		generator: NewPromptGenerator(),
		client:    client,
	}
}

// EvaluateContext evaluates a behavior context with strict parsing, 1-step retry, and envelope wrapping.
func (d *ICLDetector) EvaluateContext(behaviorContext string) (ICLResult, error) {
	return d.EvaluateContextWithInput(PromptInput{
		BehaviorContext: behaviorContext,
	})
}

// EvaluateContextWithInput evaluates a full PromptInput including computed statistical features.
func (d *ICLDetector) EvaluateContextWithInput(input PromptInput) (ICLResult, error) {
	prompt := d.generator.GeneratePromptWithInput(input)
	ctx, cancel := context.WithTimeout(context.Background(), d.config.Timeout)
	defer cancel()

	// Attempt 1: Primary LLM generation
	rawResp, err := d.client.Generate(ctx, prompt)
	if err != nil {
		// Differentiate timeout vs unavailable
		status := StatusUnavailable
		var netErr net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
			status = StatusTimeout
		}
		return d.fallbackEvaluate(input.BehaviorContext, err, status)
	}

	payload, parseErr, schemaErr := d.parseAndValidate(rawResp)
	if parseErr == nil && schemaErr == nil {
		return ICLResult{
			Engine:           EngineLLM,
			DegradedMode:     false,
			EvaluationStatus: StatusValid,
			AttemptCount:     1,
			ModelUsed:        d.config.ModelName,
			Prompt:           prompt,
			Result:           payload,
		}, nil
	}

	// Attempt 2: 1-step retry with strict JSON reminder prompt
	retryPrompt := prompt + "\n\nCRITICAL REMINDER: Your previous response failed validation. Respond ONLY in strict raw JSON without markdown formatting or code blocks."
	rawResp2, err2 := d.client.Generate(ctx, retryPrompt)
	if err2 == nil {
		payload2, parseErr2, schemaErr2 := d.parseAndValidate(rawResp2)
		if parseErr2 == nil && schemaErr2 == nil {
			return ICLResult{
				Engine:           EngineLLM,
				DegradedMode:     false,
				EvaluationStatus: StatusValid,
				AttemptCount:     2,
				ModelUsed:        d.config.ModelName,
				Prompt:           retryPrompt,
				Result:           payload2,
			}, nil
		}
		if schemaErr2 != nil {
			schemaErr = schemaErr2
		} else if parseErr2 != nil {
			parseErr = parseErr2
		}
	}

	// Final failure: return invalid envelope without substring matching
	evalStatus := StatusParseError
	errReason := ""
	if parseErr != nil {
		errReason = parseErr.Error()
	}
	if schemaErr != nil {
		evalStatus = StatusSchemaError
		errReason = schemaErr.Error()
	}

	return ICLResult{
		Engine:           EngineInvalid,
		DegradedMode:     true,
		EvaluationStatus: evalStatus,
		AttemptCount:     2,
		ModelUsed:        d.config.ModelName,
		ParseError:       errReason,
		Prompt:           prompt,
		Result: LLMResponsePayload{
			IsAttack:          false,
			Confidence:        0.0,
			Findings:          []Finding{},
			RecommendedAction: "invalid response",
		},
	}, nil
}

func (d *ICLDetector) parseAndValidate(respText string) (LLMResponsePayload, error, error) {
	rawJSON := cleanJSONResponse(respText)
	var payload LLMResponsePayload
	if err := json.Unmarshal([]byte(rawJSON), &payload); err != nil {
		return payload, fmt.Errorf("JSON parse error: %w (raw response: %s)", err, truncateString(respText, 100)), nil
	}

	if err := validatePayload(payload); err != nil {
		return payload, nil, fmt.Errorf("schema validation error: %w", err)
	}

	return payload, nil, nil
}

func validatePayload(p LLMResponsePayload) error {
	if p.Confidence < 0.0 || p.Confidence > 1.0 {
		return fmt.Errorf("confidence %.2f out of range [0.0, 1.0]", p.Confidence)
	}

	if p.IsAttack {
		if len(p.Findings) == 0 {
			return errors.New("is_attack=true requires at least 1 finding")
		}
		for i, f := range p.Findings {
			sev := strings.ToLower(f.Severity)
			if sev != "low" && sev != "medium" && sev != "high" && sev != "critical" {
				return fmt.Errorf("finding [%d] invalid severity '%s'", i, f.Severity)
			}
			if len(f.EvidenceEventIDs) == 0 {
				return fmt.Errorf("finding [%d] (%s) missing evidence_event_ids", i, f.TechniqueID)
			}
		}
	} else {
		if len(p.Findings) > 0 {
			return errors.New("is_attack=false requires findings to be an empty array []")
		}
	}

	return nil
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func cleanJSONResponse(respText string) string {
	respText = strings.TrimSpace(respText)
	if strings.HasPrefix(respText, "```") {
		lines := strings.Split(respText, "\n")
		if len(lines) >= 2 {
			if strings.HasPrefix(lines[0], "```") {
				lines = lines[1:]
			}
			if len(lines) > 0 && strings.HasPrefix(lines[len(lines)-1], "```") {
				lines = lines[:len(lines)-1]
			}
			respText = strings.Join(lines, "\n")
		}
	}
	return strings.TrimSpace(respText)
}

// Fallback heuristic evaluator for degraded execution when LLM is unavailable.
func (d *ICLDetector) fallbackEvaluate(behaviorContext string, cause error, status EvaluationStatus) (ICLResult, error) {
	ctxLower := strings.ToLower(behaviorContext)

	resPayload := LLMResponsePayload{}

	failedCount := strings.Count(ctxLower, "status=failed") + strings.Count(ctxLower, "status=401")
	notfoundCount := strings.Count(ctxLower, "status=404") + strings.Count(ctxLower, "path=/.env") + strings.Count(ctxLower, "path=/admin")

	if failedCount >= 3 {
		resPayload.IsAttack = true
		resPayload.Confidence = 0.85
		resPayload.RecommendedAction = "Temporarily rate-limit or block source IP"
		resPayload.Findings = []Finding{
			{
				TechniqueID:      "T1110",
				AttackName:       "Brute Force / Credential Access",
				Severity:         "high",
				EvidenceEventIDs: []int{1, 2, 3},
				Reasoning:        fmt.Sprintf("[In-Context Evaluation] Multiple authentication failures (%d events) observed in sliding window context, matching MITRE T1110.", failedCount),
			},
		}
	} else if notfoundCount >= 2 {
		resPayload.IsAttack = true
		resPayload.Confidence = 0.80
		resPayload.RecommendedAction = "Block scanner IP and inspect web server logs"
		resPayload.Findings = []Finding{
			{
				TechniqueID:      "T1595",
				AttackName:       "Active Scanning / Web Enumeration",
				Severity:         "medium",
				EvidenceEventIDs: []int{1, 2},
				Reasoning:        fmt.Sprintf("[In-Context Evaluation] Sensitive path probing or repeated 404 errors (%d events) detected in sliding window context, matching MITRE T1595.", notfoundCount),
			},
		}
	} else {
		resPayload.IsAttack = false
		resPayload.Confidence = 0.90
		resPayload.RecommendedAction = "monitor"
		resPayload.Findings = []Finding{}
	}

	return ICLResult{
		Engine:           EngineFallbackRule,
		DegradedMode:     true,
		EvaluationStatus: StatusValid,
		AttemptCount:     1,
		ModelUsed:        fmt.Sprintf("%s (ICL Fallback Engine: %v)", d.config.ModelName, cause),
		Result:           resPayload,
	}, nil
}
