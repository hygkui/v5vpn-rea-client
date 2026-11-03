//go:build linux

package ipsec

import (
	"context"
	"os"
)

type nativeBackend struct {
	probe *NativeProbe
	lock  *os.File
}

func NewNativeBackend(runDir string, runner CommandRunner) TunnelBackend {
	p := NewNativeProbe(runDir, runner)
	p.Journal = true
	return &nativeBackend{probe: p}
}
func (*nativeBackend) Platform() string            { return "linux" }
func (*nativeBackend) Probe(context.Context) error { return nil }
func (b *nativeBackend) Start(ctx context.Context, c Config) (StartResult, error) {
	var err error
	b.lock, err = acquireNativeLock(b.probe.RunDir)
	if err != nil {
		return StartResult{}, err
	}
	if err := recoverNativeSession(ctx, b.probe.RunDir, b.probe.Runner); err != nil {
		releaseNativeLock(b.lock)
		b.lock = nil
		return StartResult{}, err
	}
	b.probe.PeerAddress = c.PeerAddress
	err = b.probe.Start(ctx, c)
	return StartResult{}, err
}
func (b *nativeBackend) Status(ctx context.Context) (TunnelStatus, error) {
	s, err := b.probe.Status(ctx)
	return TunnelStatus{Installed: s.Installed, InBytes: s.InBytes, OutBytes: s.OutBytes}, err
}
func (b *nativeBackend) Stop(ctx context.Context, _ Config) error {
	defer func() { releaseNativeLock(b.lock); b.lock = nil }()
	return b.probe.Stop(ctx)
}
