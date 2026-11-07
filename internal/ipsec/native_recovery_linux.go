//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type diskUndo struct {
	Name string   `json:"name"`
	Args []string `json:"args"`
}
type nativeJournal struct {
	Version     int        `json:"version"`
	OwnerPID    int        `json:"ownerPid"`
	OwnerStart  string     `json:"ownerStart"`
	DaemonPID   int        `json:"daemonPid,omitempty"`
	DaemonStart string     `json:"daemonStart,omitempty"`
	VIP         string     `json:"vip"`
	Undo        []diskUndo `json:"undo"`
	Pending     *diskUndo  `json:"pending,omitempty"`
}

func processStart(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return ""
	}
	i := strings.LastIndex(string(b), ")")
	if i < 0 {
		return ""
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return ""
	}
	return f[19]
}
func (p *NativeProbe) saveJournal() error {
	if !p.Journal || !p.owned {
		return nil
	}
	j := nativeJournal{Version: 1, OwnerPID: os.Getpid(), OwnerStart: processStart(os.Getpid()), DaemonPID: p.daemonPID, DaemonStart: processStart(p.daemonPID), VIP: p.cfg.VirtualIP}
	for _, u := range p.undo {
		j.Undo = append(j.Undo, diskUndo{u.name, u.args})
	}
	if p.pending != nil {
		j.Pending = &diskUndo{p.pending.name, p.pending.args}
	}
	f, err := os.CreateTemp(p.RunDir, ".session-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = json.NewEncoder(f).Encode(j); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, filepath.Join(p.RunDir, "session.json"))
}
func checkJournalOwnership(path string) error {
	s, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || s.Mode().Perm()&0o077 != 0 || s.Mode()&os.ModeSymlink != 0 {
		return errors.New("遗留会话目录或账本权限不安全")
	}
	return nil
}

func validRecoveryOperation(u diskUndo) bool {
	if len(u.Args) > 32 {
		return false
	}
	if u.Name == "ip" {
		return len(u.Args) >= 5 && (u.Args[0] == "address" || u.Args[0] == "route" || u.Args[0] == "rule") && (u.Args[1] == "add" || u.Args[1] == "del")
	}
	return u.Name == "iptables" && len(u.Args) >= 4 && u.Args[0] == "-t" && u.Args[1] == "nat" && (u.Args[2] == "-A" || u.Args[2] == "-D" || u.Args[2] == "-I" || u.Args[2] == "-N" || u.Args[2] == "-X")
}

// Recovery uses the root-owned undo journal, checks PID start times, and
// reconciles exact objects. It never adopts a live owner or flushes a table.
func RecoverNativeSession(ctx context.Context, dir string, runner CommandRunner) error {
	lock, err := acquireNativeLock(dir)
	if err != nil {
		return err
	}
	defer releaseNativeLock(lock)
	return recoverNativeSession(ctx, dir, runner)
}

func acquireNativeLock(dir string) (*os.File, error) {
	f, err := os.OpenFile(dir+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	s, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || !s.Mode().IsRegular() || s.Mode().Perm()&0o077 != 0 {
		f.Close()
		return nil, errors.New("原生会话锁权限不安全")
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("已有内网会话正在启动、恢复或清理，请稍后重试")
	}
	return f, nil
}
func releaseNativeLock(f *os.File) {
	if f != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}
}

func recoverNativeSession(ctx context.Context, dir string, runner CommandRunner) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	}
	if err := checkJournalOwnership(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, "session.json")
	if err := checkJournalOwnership(path); err != nil {
		return errors.New("遗留会话缺少可信账本，请先核对")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var j nativeJournal
	dec := json.NewDecoder(io.LimitReader(f, 1024*1024))
	dec.DisallowUnknownFields()
	if dec.Decode(&j) != nil || j.Version != 1 || j.OwnerPID <= 0 || j.OwnerStart == "" {
		return errors.New("遗留会话账本无效")
	}
	for _, u := range j.Undo {
		if !validRecoveryOperation(u) {
			return errors.New("遗留操作格式无效")
		}
	}
	if j.Pending != nil && !validRecoveryOperation(*j.Pending) {
		return errors.New("遗留待确认操作格式无效")
	}
	if processStart(j.OwnerPID) == j.OwnerStart {
		return errors.New("已有活动的原生 IPsec 会话，请先断开")
	}
	if j.DaemonPID > 0 && j.DaemonStart != "" && processStart(j.DaemonPID) == j.DaemonStart {
		exe, e := os.Readlink(filepath.Join("/proc", strconv.Itoa(j.DaemonPID), "exe"))
		if e != nil || strings.TrimSuffix(exe, " (deleted)") != "/usr/lib/ipsec/charon" {
			return errors.New("遗留 daemon 身份不匹配")
		}
		proc, _ := os.FindProcess(j.DaemonPID)
		_ = proc.Signal(syscall.SIGTERM)
		for deadline := time.Now().Add(10 * time.Second); processStart(j.DaemonPID) == j.DaemonStart; {
			if time.Now().After(deadline) {
				return errors.New("遗留 charon 尚未退出")
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	p := NewNativeProbe(dir, runner)
	p.cfg.VirtualIP = j.VIP
	if j.Pending != nil {
		exists, e := p.effectExists(ctx, j.Pending.Name, j.Pending.Args)
		if e != nil {
			return e
		}
		if exists {
			u := append([]string(nil), j.Pending.Args...)
			if j.Pending.Name == "ip" {
				u[1] = "del"
			} else if j.Pending.Name == "iptables" {
				if u[2] == "-N" {
					u[2] = "-X"
				} else {
					u[2] = "-D"
					if j.Pending.Args[2] == "-I" {
						u = append(u[:4], u[5:]...)
					}
				}
			} else {
				return errors.New("未知遗留操作")
			}
			j.Undo = append(j.Undo, diskUndo{j.Pending.Name, u})
		}
	}
	for i := len(j.Undo) - 1; i >= 0; i-- {
		u := j.Undo[i]
		forward := append([]string(nil), u.Args...)
		if u.Name == "ip" && len(forward) > 1 && forward[1] == "del" {
			forward[1] = "add"
		} else if u.Name == "iptables" && len(forward) > 3 {
			if forward[2] == "-X" {
				forward[2] = "-N"
			} else if forward[2] == "-D" {
				forward[2] = "-A"
			} else {
				return errors.New("遗留操作无效")
			}
		} else {
			return errors.New("遗留操作无效")
		}
		exists, e := p.effectExists(ctx, u.Name, forward)
		if e != nil {
			return e
		}
		if exists {
			if _, e = p.run(ctx, u.Name, u.Args...); e != nil {
				return e
			}
		}
	}
	if err = p.xfrmEmpty(ctx); err != nil {
		return err
	}
	for _, name := range []string{"swanctl.conf", "strongswan.conf", "charon.log", "charon.vici", "charon.pid", "session.json"} {
		if e := os.Remove(filepath.Join(dir, name)); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".session-") {
			if e = checkJournalOwnership(filepath.Join(dir, entry.Name())); e != nil {
				return e
			}
			if e = os.Remove(filepath.Join(dir, entry.Name())); e != nil {
				return e
			}
		}
	}
	return os.Remove(dir)
}
