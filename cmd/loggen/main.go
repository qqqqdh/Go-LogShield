package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

// LogGenerator simulates network and authentication logs for LogShield testing.
func main() {
	outDir := flag.String("out", "./logs", "Output directory for generated logs")
	count := flag.Int("count", 100, "Number of log entries per file")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatalf("Failed to create log directory: %v", err)
	}

	fmt.Printf("🚀 Generating %d simulated test log entries in '%s'...\n", *count, *outDir)

	now := time.Now()

	// 1. Generate auth.log (Auth & SSH Brute Force patterns)
	authPath := filepath.Join(*outDir, "auth.log")
	generateAuthLog(authPath, now, *count)

	// 2. Generate ssh.log (SSH access & brute force patterns)
	sshPath := filepath.Join(*outDir, "ssh.log")
	generateSSHLog(sshPath, now, *count)

	// 3. Generate web.log (Web traffic & sensitive path enumeration T1595)
	webPath := filepath.Join(*outDir, "web.log")
	generateWebLog(webPath, now, *count)

	fmt.Println("✅ Log generation complete! Created auth.log, ssh.log, web.log")
}

func generateAuthLog(path string, startTime time.Time, count int) {
	fp, err := os.Create(path)
	if err != nil {
		log.Fatalf("Failed to create auth.log: %v", err)
	}
	defer fp.Close()

	users := []string{"alice", "bob", "charlie", "root", "admin"}
	ips := []string{"10.0.0.5", "10.0.0.12", "192.168.1.100", "203.0.113.10"}

	currTime := startTime.Add(-time.Duration(count) * time.Second)

	for i := 0; i < count; i++ {
		currTime = currTime.Add(time.Second)
		ip := ips[rand.Intn(len(ips))]
		user := users[rand.Intn(len(users))]

		// Introduce Brute Force attack pattern (IP 203.0.113.10 rapidly failing)
		status := "success"
		if ip == "203.0.113.10" || rand.Float32() < 0.3 {
			status = "FAIL"
		}

		line := fmt.Sprintf("%s service=auth action=login user=\"%s\" ip=\"%s\" status=\"%s\"\n",
			currTime.Format(time.RFC3339), user, ip, status)
		fp.WriteString(line)
	}
}

func generateSSHLog(path string, startTime time.Time, count int) {
	fp, err := os.Create(path)
	if err != nil {
		log.Fatalf("Failed to create ssh.log: %v", err)
	}
	defer fp.Close()

	ips := []string{"198.51.100.23", "10.0.0.50", "172.16.0.4"}
	currTime := startTime.Add(-time.Duration(count) * time.Second)

	for i := 0; i < count; i++ {
		currTime = currTime.Add(time.Second)
		ip := ips[rand.Intn(len(ips))]

		status := "success"
		user := "ubuntu"
		if ip == "198.51.100.23" {
			status = "failed"
			user = "root"
		}

		line := fmt.Sprintf("%s service=ssh action=login user=\"%s\" ip=\"%s\" status=\"%s\"\n",
			currTime.Format(time.RFC3339), user, ip, status)
		fp.WriteString(line)
	}
}

func generateWebLog(path string, startTime time.Time, count int) {
	fp, err := os.Create(path)
	if err != nil {
		log.Fatalf("Failed to create web.log: %v", err)
	}
	defer fp.Close()

	normalPaths := []string{"/index.html", "/about", "/login", "/dashboard", "/api/v1/user"}
	attackPaths := []string{"/.env", "/admin", "/wp-login.php", "/config.json", "/backup.sql"}
	ips := []string{"192.168.1.15", "10.0.0.99", "198.51.100.45"}

	currTime := startTime.Add(-time.Duration(count) * time.Second)

	for i := 0; i < count; i++ {
		currTime = currTime.Add(time.Second)
		ip := ips[rand.Intn(len(ips))]

		path := normalPaths[rand.Intn(len(normalPaths))]
		status := "200"

		// Introduce Web Scanning / Enumeration pattern (IP 198.51.100.45)
		if ip == "198.51.100.45" {
			path = attackPaths[rand.Intn(len(attackPaths))]
			status = "404"
		}

		line := fmt.Sprintf("%s service=web action=get user=\"guest\" ip=\"%s\" status=\"%s\" path=\"%s\"\n",
			currTime.Format(time.RFC3339), ip, status, path)
		fp.WriteString(line)
	}
}
