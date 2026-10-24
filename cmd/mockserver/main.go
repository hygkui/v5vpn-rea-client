package main

// cmd/mockserver — 保持历史命令兼容的 V5VPN mockserver 入口。
// 建议使用对齐命名的 cmd/mock-v5vpn。

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	mockserver "github.com/hygkui/v5vpn-rea-client/test/mock/v5vpn"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "TCP address to listen on (HTTPS)")
	mode := flag.String("mode", "pwd-cert", "Gateway simulation mode: pwd-cert, pwd-cert-sms, full-chain, pwd-only, pwd-change, err-auth, token, sms")
	user := flag.String("user", "admin", "Expected username")
	pwd := flag.String("pwd", "admin123", "Expected password")
	requireCert := flag.Bool("require-cert", false, "Strictly require a client TLS certificate in /vpn/user/auth/cert")
	verbose := flag.Bool("v", true, "Verbose request/response logging")
	nc := flag.String("nc", "", "NC (IPsec) portal resource fixture: \"\" none, mixed (append to TCP/UDP list), only (replace list)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of v5vpn mockserver:\n")
		fmt.Fprintf(os.Stderr, "  mockserver [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nSimulation Modes:\n")
		fmt.Fprintf(os.Stderr, "  pwd-cert   : Two-factor authentication (Password -> Challenge Code 2 -> Cert -> Code 0)\n")
		fmt.Fprintf(os.Stderr, "  pwd-cert-sms: Three-factor chain (Password -> Code 2 -> Cert -> Code 8 -> send_smc -> smc -> Code 0)\n")
		fmt.Fprintf(os.Stderr, "  full-chain : Every factor in one chain (Password+captcha -> Code 2 -> Cert -> Code 8 -> SMS -> Code 4 -> Token -> Code 0)\n")
		fmt.Fprintf(os.Stderr, "  pwd-only   : Single-factor authentication (Password -> Code 0)\n")
		fmt.Fprintf(os.Stderr, "  pwd-change : Password expired challenge (Password -> Code 256 -> PwdChange -> Code 0)\n")
		fmt.Fprintf(os.Stderr, "  err-auth   : Authentication error (Password -> Code 0x8000001a)\n")
		fmt.Fprintf(os.Stderr, "  token      : Dynamic token challenge (Password -> Code 4 -> Token -> Code 0, wrong code 0x109)\n")
		fmt.Fprintf(os.Stderr, "  sms        : SMS code challenge (Password -> Code 8 -> send_smc -> smc -> Code 0, wrong code 0x10A)\n")
	}

	flag.Parse()

	srv, err := mockserver.New(mockserver.Config{
		Addr:         *addr,
		Mode:         mockserver.Mode(*mode),
		ExpectedUser: *user,
		ExpectedPwd:  *pwd,
		RequireCert:  *requireCert,
		Verbose:      *verbose,
		NCMode:       *nc,
	})
	if err != nil {
		log.Fatalf("Failed to initialize mock server: %v", err)
	}

	fmt.Println()
	fmt.Println("🛡️  Leadsec / 网御星云 V5VPN Gateway Mock Server")
	fmt.Println("================================================================")
	fmt.Printf(" Listening On : https://%s\n", *addr)
	fmt.Printf(" Active Mode  : %s\n", *mode)
	fmt.Printf(" Credentials  : User=%q, Password=%q\n", *user, *pwd)
	fmt.Printf(" Dashboard    : https://%s/ (open in browser to toggle modes)\n", *addr)
	fmt.Println("----------------------------------------------------------------")
	fmt.Println(" Example CLI Test Command:")
	fmt.Printf("   go run ./cmd/e2e-v5vpn -gw 127.0.0.1 -port 8443 -user %s -pwd %s\n", *user, *pwd)
	fmt.Println("================================================================")
	fmt.Println()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n[MockServer] Shutting down...")
		srv.Close()
		os.Exit(0)
	}()

	if err := srv.Start(); err != nil {
		log.Fatalf("[MockServer] Server error: %v", err)
	}
}
