package ipsec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

type RouteControl interface {
	Add(context.Context, []string, string) error
	Remove(context.Context, []string, string) error
}
type windowsRoutes struct{}

func (windowsRoutes) Add(c context.Context, r []string, g string) error { return AddRoutes(c, r, g) }
func (windowsRoutes) Remove(c context.Context, r []string, g string) error {
	return RemoveRoutes(c, r, g)
}

type windowsBackend struct {
	manager *Manager
	routes  RouteControl
	mu      sync.Mutex
	gateway string
}

func NewWindowsBackend(m *Manager, r RouteControl) TunnelBackend {
	if r == nil {
		r = windowsRoutes{}
	}
	return &windowsBackend{manager: m, routes: r}
}
func (*windowsBackend) Platform() string { return "windows" }
func (b *windowsBackend) Probe(ctx context.Context) error {
	if !b.manager.Available(ctx) {
		return errors.New("WSL 发行版 v5vpn 不可用，请先运行 scripts/setup-ipsec-wsl.ps1")
	}
	return nil
}
func (b *windowsBackend) Start(ctx context.Context, c Config) (StartResult, error) {
	out, err := b.manager.Start(ctx, c)
	result := StartResult{Message: out}
	if err != nil {
		return result, err
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	gateway, err := b.manager.WSLIP(ctx, c.VirtualIP)
	if err != nil {
		result.Warnings = append(result.Warnings, "无法获取 WSL 地址，跳过 Windows 路由")
		return result, nil
	}
	b.mu.Lock()
	b.gateway = gateway
	b.mu.Unlock()
	result.Gateway = gateway
	if err = b.routes.Add(ctx, c.Routes, gateway); err != nil {
		if errors.Is(err, ErrNotElevated) {
			result.Warnings = append(result.Warnings, "IPsec 隧道已建立，但当前进程不是管理员：Windows 应用暂时无法自动路由到内网")
		} else {
			result.Warnings = append(result.Warnings, fmt.Sprintf("添加 Windows 路由失败: %v", err))
		}
	}
	return result, nil
}
func (b *windowsBackend) Status(ctx context.Context) (TunnelStatus, error) {
	s, err := b.manager.Status(ctx)
	return TunnelStatus{Installed: strings.Contains(s, "INSTALLED")}, err
}
func (b *windowsBackend) Stop(ctx context.Context, c Config) error {
	b.mu.Lock()
	g := b.gateway
	b.gateway = ""
	b.mu.Unlock()
	if g != "" {
		_ = b.routes.Remove(ctx, c.Routes, g)
	}
	return b.manager.Stop(ctx, c)
}
