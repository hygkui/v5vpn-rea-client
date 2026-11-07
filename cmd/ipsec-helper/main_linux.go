//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/hygkui/v5vpn-rea-client/internal/ipsec"
)

func main() {
	check := flag.Bool("check", false, "Read-only dependency and protocol check")
	recoverOnly := flag.Bool("recover", false, "Recover only a recorded dead native session")
	flag.Parse()
	if flag.NArg() != 0 {
		os.Exit(2)
	}
	os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	if *check {
		ok := true
		for _, name := range []string{"ip", "iptables", "swanctl", "ss", "pgrep"} {
			if _, err := exec.LookPath(name); err != nil {
				ok = false
			}
		}
		if _, err := os.Stat("/usr/lib/ipsec/charon"); err != nil {
			ok = false
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"protocol": ipsec.HelperProtocolVersion, "ok": ok})
		if !ok {
			os.Exit(1)
		}
		return
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "helper 需要系统授权")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *recoverOnly {
		if err := ipsec.RecoverNativeSession(ctx, ipsec.NativeRunDir, ipsec.ExecRunner{}); err != nil {
			fmt.Fprintln(os.Stderr, "遗留内网会话恢复失败")
			os.Exit(1)
		}
		return
	}
	// Use a duplicated descriptor so EPIPE is returned to the helper, rather
	// than Go terminating on SIGPIPE before privileged cleanup has run.
	fd, err := syscall.Dup(int(os.Stdout.Fd()))
	if err != nil {
		os.Exit(1)
	}
	syscall.CloseOnExec(fd)
	out := os.NewFile(uintptr(fd), "helper-output")
	defer out.Close()
	if err = ipsec.ServeHelper(ctx, os.Stdin, out, ipsec.NewNativeBackend(ipsec.NativeRunDir, ipsec.ExecRunner{})); err != nil {
		json.NewEncoder(out).Encode(map[string]any{"protocol": ipsec.HelperProtocolVersion, "ok": false, "error": "内网会话请求或清理失败"})
		os.Exit(1)
	}
}
