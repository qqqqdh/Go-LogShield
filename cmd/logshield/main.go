package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"go-logshield/internal/detector"
	"go-logshield/internal/normalizer"
)

func main() {
	logDir := flag.String("log-dir", "./logs", "분석할 로그 파일이 위치한 디렉터리")
	flag.Parse()

	// 1) 로그 파일 찾기
	pattern := filepath.Join(*logDir, "*.log")
	files, err := filepath.Glob(pattern)
	if err != nil {
		log.Fatal(err)
	}
	if len(files) == 0 {
		log.Fatalf("no log files found in %s", *logDir)
	}

	// 2) Detector 초기화
	bruteForceDetector := detector.NewBruteForceDetector(detector.BruteForceConfig{
		Window:    20 * time.Second,
		Threshold: 5,
	})

	sshBruteForceDetector := detector.NewSSHBruteForceDetector(
		30*time.Second,
		6,
	)

	webEnumDetector := detector.NewWebEnumDetector(
		30*time.Second,
		4,
	)

	// 3) 로그 파일 순회
	for _, file := range files {
		fmt.Println("===", file, "===")

		fp, err := os.Open(file)
		if err != nil {
			log.Fatal(err)
		}

		scanner := bufio.NewScanner(fp)
		for scanner.Scan() {
			line := scanner.Text()

			// 4) 로그 → Event 정규화
			ev, err := normalizer.ParseLine(line)
			if err != nil {
				fmt.Println("PARSE_ERR:", err, "line:", line)
				continue
			}

			// (선택) 디버그용 이벤트 출력
			fmt.Printf(
				"%s service=%s action=%s user=%s ip=%s status=%s path=%s\n",
				ev.TS.Format("15:04:05"),
				ev.Service,
				ev.Action,
				ev.User,
				ev.IP,
				ev.Status,
				ev.Path,
			)

			// 5) 로그인 브루트포스 탐지
			if r, ok := bruteForceDetector.Process(ev); ok {
				fmt.Println(r.Message)
			}

			// 6) SSH 브루트포스 탐지
			if r, ok := sshBruteForceDetector.Process(ev); ok {
				fmt.Println(r.Message)
			}

			// 7) 웹 경로 스캐닝 탐지
			if r, ok := webEnumDetector.Process(ev); ok {
				fmt.Println(r.Message)
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Println("SCAN_ERR:", err)
		}

		_ = fp.Close()
	}
}
