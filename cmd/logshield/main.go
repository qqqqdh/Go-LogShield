package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"go-logshield/internal/detector"
	"go-logshield/internal/normalizer"
)

func main() {
	files, err := filepath.Glob("./logs/*.log")
	if err != nil {
		log.Fatal(err)
	}
	if len(files) == 0 {
		log.Fatal("no log files found in ./logs/")
	}

	// Step2: BRUTE_FORCE_LOGIN detector
	bf := detector.NewBruteForceDetector(detector.BruteForceConfig{
		Window:    20 * time.Second,
		Threshold: 5,
	})

	for _, f := range files {
		fmt.Println("===", f, "===")

		fp, err := os.Open(f)
		if err != nil {
			log.Fatal(err)
		}

		sc := bufio.NewScanner(fp)
		for sc.Scan() {
			line := sc.Text()

			ev, err := normalizer.ParseLine(line)
			if err != nil {
				fmt.Println("PARSE_ERR:", err, "line:", line)
				continue
			}

			// (디버그 출력은 유지/삭제 자유)
			fmt.Printf("%s service=%s action=%s user=%s ip=%s status=%s path=%s\n",
				ev.TS.Format("15:04:05"),
				ev.Service, ev.Action, ev.User, ev.IP, ev.Status, ev.Path,
			)

			// Step2: detect & alert
			if msg, ok := bf.Process(ev); ok {
				fmt.Println(msg)
			}
		}

		if err := sc.Err(); err != nil {
			fmt.Println("SCAN_ERR:", err)
		}
		_ = fp.Close()
	}
}
