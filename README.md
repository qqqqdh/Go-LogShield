# LogShield
## Real-time Log-based Intrusion Detection System (Mini IDS with LLM In-Context Learning)

LogShield는 **Go 언어 기반의 실시간 로그 침입 탐지 시스템(Mini IDS)**으로, 기존 규칙/시그니처 기반 탐지 기능과 더불어 **LLM(LLaMA 3.1 8B) In-Context Learning(ICL)** 기반 이상 탐지, 자연어 판단 근거(Reasoning) 도출, 그리고 **학술용 정량 평가(Accuracy, Precision, Recall, F1-Score) 벤치마크 모듈**을 제공합니다.

> 📚 **학술 논문 아이디어 반영 및 베이스라인 연구**:
> 본 프로젝트는 **단국대학교 조성제 교수님 연구진 논문** (*"스마트 빌딩 냉난방공조 시스템에서 LLM 기반 네트워크 침입 탐지용 자동 프롬프트 생성 방법"*, 2026.6)의 프롬프트 자동 생성 및 행위 문맥(Behavior Context) 개념을 기반으로 개발되었습니다. 
> 
> 논문의 파인튜닝(Fine-tuning) 모델(F1 1.0) 대비 **"자원이 제한된 환경에서 파인튜닝 없이 In-Context Learning(ICL)만으로 LLaMA 3.1 8B 모델의 침입 탐지 성능 및 설명 가능성을 검증하는 비교 베이스라인"**을 실증 구현하였습니다.

---

## 🏗️ 서브 프로젝트 및 CLI 구조 (`cmd/`)

- **`cmd/logshield`**: 실시간 CLI 파이프라인 분석기 (Rule + LLM ICL Engine)
- **`cmd/logshield-tui`**: Bubbletea 기반 실시간 TUI 모니터링 대시보드
- **`cmd/loggen`**: 테스트용 시뮬레이션 로그 생성기 (`auth.log`, `ssh.log`, `web.log`)
- **`cmd/benchmark`**: **학술용 ICL 정량 평가 벤치마크 도구 (Accuracy, Precision, Recall, F1-Score, Confusion Matrix 자동 계산)**

---

## 🌟 주요 기능

### 1. 슬라이딩 윈도우 기반 행위 문맥 합성 (Behavior Context Aggregator)
- 단일 로그/패킷 분석의 한계를 극복하기 위해, 일정 시간/개수의 윈도우(Sliding Window) 내 발생한 로그 스트림을 자연어 텍스트 문맥(`BehaviorContext`)으로 결합합니다.

### 2. MITRE ATT&CK 기반 ICL 프롬프트 생성기 (Prompt Generator)
- 논문 표 1 및 표 2의 프롬프트 구조(Role + Detection Questions + Definition + Behavior Context)를 변환.
- MITRE ATT&CK 주요 기법 (**T1110 Brute Force**, **T1595 Web Enumeration**, **T1078 Valid Accounts**, **T1499 DoS**, **T1059 Command Execution**) 탐지 질의문 및 Few-shot 예시 포함.

### 3. LLaMA 3.1 8B In-Context Learning (ICL) 탐지 엔진
- Local Ollama API (`llama3.1:8b`) 연동 또는 ICL Fallback 엔진을 통해 파인튜닝 없이 LLM에 프롬프트를 전달합니다.
- 탐지 여부(`is_attack`), MITRE 기법 ID (`technique_id`), 그리고 **자연어 판단 근거 (`reasoning`)**를 자동 산출합니다.

### 4. 학술용 정량 평가 벤치마크 모듈 (`internal/benchmark`)
- Ground Truth 테스트 데이터셋을 대상으로 ICL 모델을 평가하여 **Accuracy, Precision, Recall, F1-Score** 및 Confusion Matrix를 자동 계산하고 `benchmark_report.json`으로 출력합니다.

---

## 🚀 실행 및 테스트 방법

### 1. 테스트 로그 생성 (시뮬레이션)
```bash
go run cmd/loggen/main.go
```

### 2. LogShield IDS 실행 (CLI 분석기)
```bash
# 기본 실행
go run cmd/logshield/main.go

# 생성된 프롬프트 전문 확인 옵션
go run cmd/logshield/main.go -print-prompt
```

### 3. 실시간 TUI 모니터링 대시보드 실행
```bash
go run cmd/logshield-tui/main.go
```

### 4. ICL 정량 평가 벤치마크 실행 (Accuracy & F1-Score 산출)
```bash
go run cmd/benchmark/main.go
```

---

## 📊 벤치마크 측정 결과 예시 (`benchmark_report.json`)

```json
{
  "total_samples": 7,
  "true_positive": 3,
  "false_positive": 0,
  "true_negative": 3,
  "false_negative": 1,
  "accuracy": 0.8571,
  "precision": 1.0,
  "recall": 0.75,
  "f1_score": 0.8571
}
```