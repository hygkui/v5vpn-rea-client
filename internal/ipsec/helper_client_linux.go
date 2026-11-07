//go:build linux

package ipsec

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
)

type helperProcess struct {
	in         io.WriteCloser
	out        io.ReadCloser
	reader     *bufio.Reader
	replies    <-chan []byte
	done       <-chan struct{}
	waitErr    func() error
	cancelAuth func()
	closed     sync.Once
}
type linuxBackend struct {
	peer    string
	mu      sync.Mutex
	rpc     sync.Mutex
	process *helperProcess
	check   func(context.Context) error
	launch  func() (*helperProcess, error)
}

func newLinuxBackend(peer string) *linuxBackend {
	return &linuxBackend{peer: peer, check: checkInstalledHelper, launch: launchInstalledHelper}
}
func NewLinuxBackend(_ string, peer string) TunnelBackend { return newLinuxBackend(peer) }
func (*linuxBackend) Platform() string                    { return "linux" }
func (b *linuxBackend) Probe(ctx context.Context) error   { return b.check(ctx) }

func trustedHelper() error {
	for p := HelperPath; ; p = filepath.Dir(p) {
		s, err := os.Lstat(p)
		if err != nil {
			return errors.New("原生 IPsec helper 未安装，请运行 scripts/setup-ipsec-linux.sh")
		}
		st, ok := s.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || s.Mode().Perm()&0o022 != 0 || s.Mode()&os.ModeSymlink != 0 {
			return errors.New("IPsec helper 或安装目录权限不安全")
		}
		if p == HelperPath && (!s.Mode().IsRegular() || s.Mode().Perm()&0o111 == 0) {
			return errors.New("IPsec helper 不是有效的可执行文件")
		}
		if p == "/" {
			return nil
		}
	}
}
func checkInstalledHelper(ctx context.Context) error {
	if err := trustedHelper(); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, HelperPath, "--check")
	data, err := cmd.Output()
	if err != nil {
		return errors.New("原生 IPsec 依赖不完整，请运行 scripts/setup-ipsec-linux.sh --check")
	}
	var r helperReply
	if json.Unmarshal(data, &r) != nil || !r.OK || r.Protocol != HelperProtocolVersion {
		return errors.New("IPsec helper 版本不匹配，请重新安装")
	}
	return nil
}
func launchInstalledHelper() (*helperProcess, error) {
	if err := trustedHelper(); err != nil {
		return nil, err
	}
	cmd := exec.Command("/usr/bin/pkexec", "--disable-internal-agent", HelperPath)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	for _, key := range []string{"DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		if v := os.Getenv(key); v != "" {
			cmd.Env = append(cmd.Env, key+"="+v)
		}
	}
	return startHelperProcess(cmd)
}

func startHelperProcess(cmd *exec.Cmd) (*helperProcess, error) {
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		in.Close()
		out.Close()
		return nil, errors.New("无法启动系统授权")
	}
	done := make(chan struct{})
	frames := make(chan []byte, 4)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		defer close(frames)
		scanner := bufio.NewScanner(out)
		scanner.Buffer(make([]byte, 4096), 65536)
		for scanner.Scan() {
			data := append([]byte(nil), scanner.Bytes()...)
			select {
			case frames <- data:
			default:
				_ = in.Close()
				return
			}
		}
		if scanner.Err() != nil {
			_ = in.Close()
		}
	}()
	var waitErr error
	go func() { <-readDone; waitErr = cmd.Wait(); close(done) }()
	return &helperProcess{in: in, out: out, replies: frames, done: done, waitErr: func() error { return waitErr }, cancelAuth: func() { _ = cmd.Process.Signal(syscall.SIGTERM) }}, nil
}
func (b *linuxBackend) closeSession() {
	b.mu.Lock()
	p := b.process
	b.mu.Unlock()
	if p != nil {
		p.closed.Do(func() {
			_ = p.in.Close()
			if p.cancelAuth != nil {
				p.cancelAuth()
			}
		})
	}
}
func helperExitError(p *helperProcess) error {
	err := p.waitErr()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		switch exit.ExitCode() {
		case 126:
			return errors.New("系统授权已取消，内网隧道未建立")
		case 127:
			return errors.New("系统授权失败，请检查桌面授权服务")
		}
	}
	if err != nil {
		return errors.New("原生 IPsec helper 退出异常，请检查清理状态")
	}
	return errors.New("原生 IPsec helper 会话已结束")
}
func (b *linuxBackend) request(ctx context.Context, r helperRequest) (helperReply, error) {
	b.rpc.Lock()
	defer b.rpc.Unlock()
	b.mu.Lock()
	p := b.process
	b.mu.Unlock()
	if p == nil {
		return helperReply{}, errors.New("无活动的 IPsec helper")
	}
	stop := context.AfterFunc(ctx, b.closeSession)
	defer stop()
	data, err := json.Marshal(r)
	if err != nil || len(data) >= 65536 {
		return helperReply{}, errors.New("IPsec 会话配置超过消息限制")
	}
	_, err = p.in.Write(append(data, '\n'))
	if err == nil || p.replies != nil {
		var line []byte
		if p.replies != nil {
			select {
			case data, ok := <-p.replies:
				if ok {
					line = data
					err = nil
				} else {
					err = io.EOF
				}
			case <-ctx.Done():
				err = ctx.Err()
			}
		} else {
			if p.reader == nil {
				p.reader = bufio.NewReaderSize(p.out, 65536)
			}
			line, err = p.reader.ReadSlice('\n')
		}
		if err == nil {
			var reply helperReply
			if json.Unmarshal(line, &reply) != nil || reply.Protocol != HelperProtocolVersion {
				b.closeSession()
				return helperReply{}, errors.New("IPsec helper 响应无效")
			}
			if !reply.OK {
				return reply, errors.New(reply.Error)
			}
			return reply, nil
		}
	}
	b.closeSession()
	if ctx.Err() != nil {
		return helperReply{}, ctx.Err()
	}
	select {
	case <-p.done:
		return helperReply{}, helperExitError(p)
	case <-ctx.Done():
		return helperReply{}, ctx.Err()
	}
}
func (b *linuxBackend) Start(ctx context.Context, c Config) (StartResult, error) {
	peer := net.ParseIP(b.peer)
	if peer == nil || peer.To4() == nil || peer.IsLoopback() || peer.IsUnspecified() || peer.IsMulticast() {
		return StartResult{}, errors.New("原生 IPsec 需要本次已认证网关的 IPv4 地址")
	}
	if _, err := normalizeNativeProfile(c); err != nil {
		return StartResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return StartResult{}, err
	}
	p, err := b.launch()
	if err != nil {
		return StartResult{}, err
	}
	b.mu.Lock()
	b.process = p
	b.mu.Unlock()
	_, err = b.request(ctx, helperRequest{Protocol: HelperProtocolVersion, Op: "start", Peer: peer.String(), Config: &c})
	if err != nil {
		b.closeSession()
		return StartResult{}, err
	}
	return StartResult{Message: "原生 IPsec 内网连接已就绪"}, nil
}
func (b *linuxBackend) Status(ctx context.Context) (TunnelStatus, error) {
	r, err := b.request(ctx, helperRequest{Protocol: HelperProtocolVersion, Op: "status"})
	return r.Status, err
}
func (b *linuxBackend) Stop(ctx context.Context, _ Config) error {
	b.closeSession()
	b.mu.Lock()
	p := b.process
	b.mu.Unlock()
	if p == nil {
		return nil
	}
	select {
	case <-p.done:
		if p.waitErr() != nil {
			return helperExitError(p)
		}
		return nil
	case <-ctx.Done():
		return errors.New("原生 IPsec 清理尚未完成，请检查 helper 状态")
	}
}
