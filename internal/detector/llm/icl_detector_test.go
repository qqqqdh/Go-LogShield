package llm

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mockInferenceClient struct {
	responses []string
	errors    []error
	callCount int
}

func (m *mockInferenceClient) Generate(ctx context.Context, prompt string) (string, error) {
	idx := m.callCount
	m.callCount++
	if idx < len(m.errors) && m.errors[idx] != nil {
		return "", m.errors[idx]
	}
	if idx < len(m.responses) {
		return m.responses[idx], nil
	}
	return "", errors.New("no mock response set")
}

func TestEvaluateContext_ValidAttack(t *testing.T) {
	mockClient := &mockInferenceClient{
		responses: []string{
			`{"is_attack": true, "confidence": 0.92, "findings": [{"technique_id": "T1110", "attack_name": "Brute Force", "severity": "high", "evidence_event_ids": [1, 2], "reasoning": "Failed logins"}], "recommended_action": "Block IP"}`,
		},
	}

	detector := NewICLDetectorWithClient(ICLDetectorConfig{
		ModelName: "mock-model",
		Timeout:   5 * time.Second,
	}, mockClient)

	res, err := detector.EvaluateContext("sample context")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Engine != EngineLLM {
		t.Errorf("expected engine %s, got %s", EngineLLM, res.Engine)
	}
	if res.EvaluationStatus != StatusValid {
		t.Errorf("expected status %s, got %s", StatusValid, res.EvaluationStatus)
	}
	if res.DegradedMode {
		t.Errorf("expected DegradedMode=false")
	}
	if !res.Result.IsAttack {
		t.Errorf("expected IsAttack=true")
	}
	if res.AttemptCount != 1 {
		t.Errorf("expected AttemptCount=1, got %d", res.AttemptCount)
	}
}

func TestEvaluateContext_ValidNormal(t *testing.T) {
	mockClient := &mockInferenceClient{
		responses: []string{
			`{"is_attack": false, "confidence": 0.98, "findings": [], "recommended_action": "monitor"}`,
		},
	}

	detector := NewICLDetectorWithClient(ICLDetectorConfig{
		ModelName: "mock-model",
		Timeout:   5 * time.Second,
	}, mockClient)

	res, err := detector.EvaluateContext("sample context")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Engine != EngineLLM {
		t.Errorf("expected engine %s, got %s", EngineLLM, res.Engine)
	}
	if res.Result.IsAttack {
		t.Errorf("expected IsAttack=false")
	}
	if len(res.Result.Findings) != 0 {
		t.Errorf("expected 0 findings for normal result, got %d", len(res.Result.Findings))
	}
}

func TestEvaluateContext_ParseErrorRetrySuccess(t *testing.T) {
	mockClient := &mockInferenceClient{
		responses: []string{
			`This is not JSON but text explaining attack true`, // Fail 1
			`{"is_attack": true, "confidence": 0.88, "findings": [{"technique_id": "T1110", "attack_name": "Brute Force", "severity": "high", "evidence_event_ids": [1], "reasoning": "Valid JSON retry"}], "recommended_action": "Block"}`, // Retry success
		},
	}

	detector := NewICLDetectorWithClient(ICLDetectorConfig{
		ModelName: "mock-model",
		Timeout:   5 * time.Second,
	}, mockClient)

	res, err := detector.EvaluateContext("sample context")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Engine != EngineLLM {
		t.Errorf("expected engine %s, got %s", EngineLLM, res.Engine)
	}
	if res.AttemptCount != 2 {
		t.Errorf("expected AttemptCount=2, got %d", res.AttemptCount)
	}
	if res.EvaluationStatus != StatusValid {
		t.Errorf("expected StatusValid, got %s", res.EvaluationStatus)
	}
}

func TestEvaluateContext_ParseErrorFinalInvalid(t *testing.T) {
	mockClient := &mockInferenceClient{
		responses: []string{
			`This looks like an attack`, // Fail 1
			`Still free text response`,  // Fail 2
		},
	}

	detector := NewICLDetectorWithClient(ICLDetectorConfig{
		ModelName: "mock-model",
		Timeout:   5 * time.Second,
	}, mockClient)

	res, err := detector.EvaluateContext("sample context")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Engine != EngineInvalid {
		t.Errorf("expected EngineInvalid, got %s", res.Engine)
	}
	if res.EvaluationStatus != StatusParseError {
		t.Errorf("expected StatusParseError, got %s", res.EvaluationStatus)
	}
	if !res.DegradedMode {
		t.Errorf("expected DegradedMode=true for invalid result")
	}
	if res.AttemptCount != 2 {
		t.Errorf("expected AttemptCount=2, got %d", res.AttemptCount)
	}
	// Verify that string contains "attack" did NOT force IsAttack=true!
	if res.Result.IsAttack {
		t.Errorf("IsAttack must NOT be coerced to true on parse failure")
	}
}

func TestEvaluateContext_SchemaErrorInvalid(t *testing.T) {
	mockClient := &mockInferenceClient{
		responses: []string{
			`{"is_attack": true, "confidence": 0.90, "findings": []}`, // Invalid: attack=true requires findings
			`{"is_attack": true, "confidence": 0.90, "findings": []}`, // Invalid again
		},
	}

	detector := NewICLDetectorWithClient(ICLDetectorConfig{
		ModelName: "mock-model",
		Timeout:   5 * time.Second,
	}, mockClient)

	res, err := detector.EvaluateContext("sample context")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Engine != EngineInvalid {
		t.Errorf("expected EngineInvalid, got %s", res.Engine)
	}
	if res.EvaluationStatus != StatusSchemaError {
		t.Errorf("expected StatusSchemaError, got %s", res.EvaluationStatus)
	}
}

func TestEvaluateContext_NetworkFailureFallback(t *testing.T) {
	mockClient := &mockInferenceClient{
		errors: []error{
			errors.New("connection refused"),
		},
	}

	detector := NewICLDetectorWithClient(ICLDetectorConfig{
		ModelName: "mock-model",
		Timeout:   5 * time.Second,
	}, mockClient)

	sampleCtx := "(1) At 14:00:01, IP 10.0.0.1 performed service=ssh action=login status=failed user=root\n(2) At 14:00:02, IP 10.0.0.1 performed service=ssh action=login status=failed user=root\n(3) At 14:00:03, IP 10.0.0.1 performed service=ssh action=login status=failed user=root"
	res, err := detector.EvaluateContext(sampleCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Engine != EngineFallbackRule {
		t.Errorf("expected EngineFallbackRule on network failure, got %s", res.Engine)
	}
	if !res.DegradedMode {
		t.Errorf("expected DegradedMode=true on fallback")
	}
	if res.EvaluationStatus != StatusValid {
		t.Errorf("expected StatusValid for successful fallback execution, got %s", res.EvaluationStatus)
	}
	if !res.Result.IsAttack {
		t.Errorf("expected fallback rule to detect attack for 3 failed logins")
	}
}
