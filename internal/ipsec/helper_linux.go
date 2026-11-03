//go:build linux

package ipsec

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const HelperProtocolVersion = 1
const HelperPath = "/usr/local/libexec/v5vpn-rea-ipsec-helper"
const NativeRunDir = "/run/v5vpn-native-ipsec"

type helperRequest struct {
	Protocol int     `json:"protocol"`
	Op       string  `json:"op"`
	Config   *Config `json:"config,omitempty"`
	Peer     string  `json:"peer,omitempty"`
}
type helperReply struct {
	Protocol int          `json:"protocol"`
	OK       bool         `json:"ok"`
	Status   TunnelStatus `json:"status,omitempty"`
	Error    string       `json:"error,omitempty"`
}

// ServeHelper owns one authenticated pipe, and one session. Closing the UI's
// write end cancels startup and always tears down privileged network objects.
func ServeHelper(ctx context.Context, in io.Reader, out io.Writer, backend TunnelBackend) (retErr error) {
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	var cfg Config
	active := false
	defer func() {
		if active {
			cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
			defer done()
			retErr = errors.Join(retErr, backend.Stop(cleanup, cfg))
		}
	}()
	type incoming struct {
		req helperRequest
		err error
	}
	messages := make(chan incoming)
	var startupMu sync.Mutex
	var cancelStart context.CancelFunc
	stopping := false
	go func() {
		defer cancel()
		s := bufio.NewScanner(in)
		s.Buffer(make([]byte, 4096), 65536)
		for s.Scan() {
			var req helperRequest
			d := json.NewDecoder(strings.NewReader(s.Text()))
			d.DisallowUnknownFields()
			err := d.Decode(&req)
			if err == nil {
				var trailing any
				if e := d.Decode(&trailing); e != io.EOF {
					err = errors.New("请求必须只包含一个 JSON 对象")
				}
			}
			if err == nil && (req.Protocol != HelperProtocolVersion || (req.Op != "start" && req.Op != "status" && req.Op != "stop")) {
				err = errors.New("不支持的 helper 请求")
			}
			if req.Op == "stop" {
				startupMu.Lock()
				stopping = true
				if cancelStart != nil {
					cancelStart()
				}
				startupMu.Unlock()
			}
			select {
			case messages <- incoming{req, err}:
			case <-life.Done():
				return
			}
			if err != nil {
				return
			}
		}
		if s.Err() != nil {
			select {
			case messages <- incoming{err: errors.New("helper 请求超过 64 KiB 或读取失败")}:
			case <-life.Done():
			}
		}
	}()
	enc := json.NewEncoder(out)
	reply := func(r helperReply) error { r.Protocol = HelperProtocolVersion; return enc.Encode(r) }
	for {
		select {
		case <-life.Done():
			return nil
		case msg := <-messages:
			if msg.err != nil {
				_ = reply(helperReply{Error: "helper 请求格式无效"})
				return msg.err
			}
			r := msg.req
			switch r.Op {
			case "start":
				if active || r.Config == nil {
					return errors.New("helper 只能管理一个有效会话")
				}
				peer := net.ParseIP(r.Peer)
				if peer == nil || peer.To4() == nil || peer.IsLoopback() || peer.IsUnspecified() || peer.IsMulticast() {
					return errors.New("缺少有效的已认证网关 IPv4 地址")
				}
				var err error
				cfg, err = normalizeNativeProfile(*r.Config)
				if err != nil {
					return err
				}
				cfg.PeerAddress = peer.String()
				active = true
				start, done := context.WithTimeout(life, 90*time.Second)
				startupMu.Lock()
				cancelStart = done
				if stopping {
					done()
				}
				startupMu.Unlock()
				_, err = backend.Start(start, cfg)
				done()
				startupMu.Lock()
				cancelStart = nil
				startupMu.Unlock()
				if err != nil {
					_ = reply(helperReply{Error: "IPsec 建立失败: " + err.Error()})
					return nil
				}
				if err = reply(helperReply{OK: true}); err != nil {
					return nil
				}
			case "status":
				if r.Config != nil || r.Peer != "" || !active {
					return errors.New("无有效 helper 会话")
				}
				query, done := context.WithTimeout(life, 5*time.Second)
				status, err := backend.Status(query)
				done()
				r := helperReply{OK: err == nil, Status: status}
				if err != nil {
					r.Error = "无法查询本次隧道"
				}
				if reply(r) != nil {
					return nil
				}
			case "stop":
				if r.Config != nil || r.Peer != "" {
					return errors.New("stop 不接受配置")
				}
				cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
				err := backend.Stop(cleanup, cfg)
				done()
				active = false
				resp := helperReply{OK: err == nil}
				if err != nil {
					resp.Error = "IPsec 清理失败: " + err.Error()
				}
				_ = reply(resp)
				return err
			}
		}
	}
}
