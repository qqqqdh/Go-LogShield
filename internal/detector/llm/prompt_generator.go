package llm

import (
	"fmt"
	"strings"
)

// PromptGenerator creates structured prompts combining MITRE ATT&CK queries and Behavior Context
// as proposed in the KIISE paper ("Automatic Prompt Generation for LLM-based NIDS").
type PromptGenerator struct {
	RoleDefinition string
	Techniques     []MITRETechnique
}

type MITRETechnique struct {
	ID          string
	Name        string
	Question    string
}

// NewPromptGenerator initializes default MITRE ATT&CK for IT/Web techniques.
func NewPromptGenerator() *PromptGenerator {
	return &PromptGenerator{
		RoleDefinition: "Your role is a network/system log-based intrusion detection system (NIDS). Analyze the provided log behavior context and evaluate if any attack techniques are present.",
		Techniques: []MITRETechnique{
			{
				ID:       "T1110",
				Name:     "Brute Force / Credential Access",
				Question: "Are there multiple failed authentication attempts (status=failed/401) from the same IP within a short time frame?",
			},
			{
				ID:       "T1595",
				Name:     "Active Scanning / Web Enumeration",
				Question: "Is an IP attempting to access sensitive or non-existent paths (e.g., /.env, /admin, 404 responses) repeatedly?",
			},
			{
				ID:       "T1078",
				Name:     "Valid Accounts / Account Hijacking",
				Question: "Is there a sudden successful login (status=success) following multiple failed attempts or from an unusual IP?",
			},
			{
				ID:       "T1499",
				Name:     "Endpoint Denial of Service",
				Question: "Is an abnormally high volume of requests occurring in a very short window, attempting to overwhelm the service?",
			},
			{
				ID:       "T1059",
				Name:     "Command and Scripting Interpreter Execution",
				Question: "Are suspicious parameters or command execution paths being accessed by unauthorized or guest users?",
			},
		},
	}
}

// GeneratePrompt constructs an In-Context Learning (ICL) prompt for LLM inference.
func (g *PromptGenerator) GeneratePrompt(behaviorContext string) string {
	var sb strings.Builder

	// 1. Role
	sb.WriteString(fmt.Sprintf("=== ROLE ===\n%s\n\n", g.RoleDefinition))

	// 2. Questions (MITRE ATT&CK Based)
	sb.WriteString("=== MITRE ATT&CK DETECTION QUESTIONS ===\n")
	sb.WriteString("Based on the log behavior context, evaluate the following attack techniques:\n")
	for i, tech := range g.Techniques {
		sb.WriteString(fmt.Sprintf("%d. [%s] %s: %s\n", i+1, tech.ID, tech.Name, tech.Question))
	}
	sb.WriteString("\n")

	// 3. In-Context Learning Examples (Few-Shot)
	sb.WriteString("=== IN-CONTEXT LEARNING EXAMPLES ===\n")
	sb.WriteString("Example 1 (Normal Behavior):\n")
	sb.WriteString("Context: (1) At 14:00:01, IP 10.0.0.1 performed service=web action=get status=200 path=/index.html\n")
	sb.WriteString("Response: {\"is_attack\": false, \"technique_id\": \"None\", \"attack_name\": \"Normal\", \"reasoning\": \"Standard web GET request with 200 OK status.\"}\n\n")

	sb.WriteString("Example 2 (Attack Behavior):\n")
	sb.WriteString("Context: (1) At 14:00:05, IP 192.168.1.50 performed service=ssh action=login status=failed user=root\n")
	sb.WriteString("         (2) At 14:00:06, IP 192.168.1.50 performed service=ssh action=login status=failed user=root\n")
	sb.WriteString("         (3) At 14:00:07, IP 192.168.1.50 performed service=ssh action=login status=failed user=admin\n")
	sb.WriteString("Response: {\"is_attack\": true, \"technique_id\": \"T1110\", \"attack_name\": \"Brute Force / Credential Access\", \"reasoning\": \"Multiple rapid failed SSH login attempts detected from IP 192.168.1.50 targeting sensitive accounts.\"}\n\n")

	// 4. Definition & Instruction
	sb.WriteString("=== TARGET BEHAVIOR CONTEXT TO ANALYZE ===\n")
	sb.WriteString(behaviorContext)
	sb.WriteString("\n")

	// 5. Output Constraint
	sb.WriteString("=== RESPONSE INSTRUCTIONS ===\n")
	sb.WriteString("Analyze the target behavior context above and respond ONLY in strict JSON format as shown below, without any markdown formatting or commentary:\n")
	sb.WriteString("{\n")
	sb.WriteString("  \"is_attack\": true or false,\n")
	sb.WriteString("  \"technique_id\": \"TXXXX or None\",\n")
	sb.WriteString("  \"attack_name\": \"Technique Name or Normal\",\n")
	sb.WriteString("  \"reasoning\": \"Explain the specific log evidence and logic for your decision\"\n")
	sb.WriteString("}\n")

	return sb.String()
}
