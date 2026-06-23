package detector

// Result는 탐지기가 경고를 발생시킬 때 반환하는 구조체입니다.
// Process()가 문자열 대신 이 구조체를 반환하므로,
// 호출자가 메시지 문자열을 직접 파싱할 필요가 없습니다.
type Result struct {
	RuleID   string // 예: "BRUTE_FORCE_LOGIN"
	Title    string // 사람이 읽는 제목
	Severity string // "낮음" | "중간" | "높음" | "치명"
	Message  string // 전체 경고 메시지 (터미널 출력용)
	IP       string
	Service  string
}
