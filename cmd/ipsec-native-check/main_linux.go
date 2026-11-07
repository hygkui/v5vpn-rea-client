//go:build linux

// ipsec-native-check is a root-only, explicitly requested tunnel validation
// tool. It does not alter the desktop client's login or platform selection.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hygkui/v5vpn-rea-client/internal/ipsec"
)

type result struct {
	ipsec.NativeProbeStatus
	HTTPStatus  int      `json:"target_http_status,omitempty"`
	Cleanup     bool     `json:"cleanup_complete"`
	Error       string   `json:"error,omitempty"`
	Diagnostics []string `json:"diagnostics,omitempty"`
	RXDelta     uint64   `json:"request_rx_delta"`
	TXDelta     uint64   `json:"request_tx_delta"`
}

func verifyFlow(before, after ipsec.NativeProbeStatus, code int) error {
	if !before.Installed || !after.Installed || code < 200 || code >= 400 || after.InBytes <= before.InBytes || after.OutBytes <= before.OutBytes {
		return errors.New("尚未证明目标成功响应及本次双向 ESP 流量增量")
	}
	return nil
}

func probeHTTP(ctx context.Context, target string, insecure bool) (int, error) {
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Hostname() != via[0].URL.Hostname() {
			return errors.New("redirect outside the protected validation target")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, errors.New("目标 HTTP/TLS 连接失败；证书例外须显式指定 -insecure-target")
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return resp.StatusCode, errors.New("目标响应读取失败")
	}
	return resp.StatusCode, nil
}

func execute(ctx context.Context, portal, target, peer string, insecure bool, hold time.Duration) (out result, err error) {
	out.Cleanup = true
	if os.Geteuid() != 0 {
		return out, errors.New("原生验证入口必须以 root 身份执行")
	}
	cfg, err := ipsec.ReadNativeProfile(portal)
	if err != nil {
		return out, err
	}
	if target != "" {
		if err = ipsec.CheckNativeTarget(cfg, target); err != nil {
			return out, err
		}
	}
	probe := ipsec.NewNativeProbe("/run/v5vpn-native-check", nil)
	probe.PeerAddress = peer
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		e := probe.Stop(cleanup)
		out.Cleanup = e == nil
		err = errors.Join(err, e)
		if err != nil {
			out.Diagnostics = probe.Diagnostics
		}
	}()
	startup, cancel := context.WithTimeout(ctx, 90*time.Second)
	err = probe.Start(startup, cfg)
	cancel()
	if err != nil {
		return out, err
	}
	out.NativeProbeStatus, err = probe.Status(ctx)
	if err != nil {
		return out, err
	}
	if target != "" {
		if err = probe.VerifyTargetRoute(ctx, target); err != nil {
			return out, err
		}
		before := out.NativeProbeStatus
		out.HTTPStatus, err = probeHTTP(ctx, target, insecure)
		time.Sleep(250 * time.Millisecond)
		query, done := context.WithTimeout(context.Background(), 5*time.Second)
		after, e := probe.Status(query)
		done()
		if e != nil {
			return out, errors.Join(err, e)
		}
		out.NativeProbeStatus = after
		if after.InBytes >= before.InBytes {
			out.RXDelta = after.InBytes - before.InBytes
		}
		if after.OutBytes >= before.OutBytes {
			out.TXDelta = after.OutBytes - before.OutBytes
		}
		if err == nil {
			err = verifyFlow(before, after, out.HTTPStatus)
		}
		if err != nil {
			return out, err
		}
	}
	if hold > 0 {
		fmt.Fprintln(os.Stderr, "原生隧道暂时保持连接；Ctrl+C 会清理。")
		select {
		case <-ctx.Done():
		case <-time.After(hold):
		}
	}
	// Kernel byte counters may be published shortly after the HTTP response.
	time.Sleep(250 * time.Millisecond)
	query, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	status, e := probe.Status(query)
	if e == nil {
		out.NativeProbeStatus = status
	} else {
		err = errors.Join(err, e)
	}
	if err == nil && !status.Installed {
		err = errors.New("最终 Child SA 未就绪")
	}
	return out, err
}

func main() {
	portal := flag.String("portal", "", "当前会话的私有 NC portal XML（0600）")
	target := flag.String("target", "", "保护网段中的 HTTP/HTTPS IPv4 URL")
	peer := flag.String("peer-address", "", "显式 NAT 传输地址；不改写 XML 中的远端 IKE 身份")
	insecure := flag.Bool("insecure-target", false, "仅对指定验证目标接受未受信任的 TLS 证书")
	hold := flag.Duration("hold", 0, "验证后保持隧道的时间（最长 5 分钟）；Ctrl+C 清理")
	flag.Parse()
	if *portal == "" || *hold < 0 || *hold > 5*time.Minute {
		fmt.Fprintln(os.Stderr, "需要 -portal；-hold 必须介于 0 和 5m")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	out, err := execute(ctx, *portal, *target, *peer, *insecure, *hold)
	if err != nil {
		out.Error = err.Error()
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	if err != nil {
		os.Exit(1)
	}
}
