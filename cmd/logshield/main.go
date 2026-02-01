package normalizer

import (
	"errors"
	"strings"
	"time"
)

type Event struct {
	TS      time.Time
	Service string
	Action  string
	User    string
	IP      string
	Status  string
	Path    string
	RawLine string
}

func ParseLine(line string) (Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Event{}, errors.New("empty line")
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return Event{}, errors.New("invalid line format")
	}

	// 1) timestamp (첫 토큰)
	ts, err := time.Parse(time.RFC3339, parts[0])
	if err != nil {
		return Event{}, err
	}

	ev := Event{
		TS:      ts,
		RawLine: line,
	}

	// 2) key=value 토큰 파싱
	for _, tok := range parts[1:] {
		kv := strings.SplitN(tok, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := kv[0], kv[1]
		v = strings.Trim(v, `"`)

		switch k {
		case "service":
			ev.Service = v
		case "action":
			ev.Action = v
		case "user":
			ev.User = v
		case "ip":
			ev.IP = v
		case "status":
			ev.Status = v
		case "path":
			ev.Path = v
			// web.log에는 method, ua도 있지만 Step 1에서는 무시해도 OK
		}
	}

	// 최소 필수: service 없으면 의미가 애매해서 에러 처리
	if ev.Service == "" {
		return Event{}, errors.New("missing service field")
	}

	return ev, nil
}
