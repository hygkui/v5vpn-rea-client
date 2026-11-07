//go:build linux && ipsectest

package ipsec

// This factory only exists in explicitly tagged E2E binaries. Production
// builds do not read these variables or allow a substitute privileged helper.
import (
	"context"
	"errors"
	"os"
)

type fixtureBackend struct{ mode string }

func PlatformName() string { return "linux" }
func NewPlatformBackend(string, string) TunnelBackend {
	return fixtureBackend{mode: os.Getenv("V5VPN_IPSEC_TEST_STATE")}
}
func (fixtureBackend) Platform() string { return "linux" }
func (b fixtureBackend) Probe(context.Context) error {
	if b.mode == "up" || b.mode == "error" || b.mode == "authorization-cancelled" {
		return nil
	}
	return errors.New("Linux 内网连接环境尚未准备")
}
func (b fixtureBackend) Start(context.Context, Config) (StartResult, error) {
	switch b.mode {
	case "up":
		return StartResult{}, nil
	case "authorization-cancelled":
		return StartResult{}, errors.New("系统授权已取消，请重新连接后完成授权")
	}
	return StartResult{}, errors.New("内网连接建立失败，请重新连接")
}
func (b fixtureBackend) Status(context.Context) (TunnelStatus, error) {
	return TunnelStatus{Installed: b.mode == "up"}, nil
}
func (fixtureBackend) Stop(context.Context, Config) error { return nil }
