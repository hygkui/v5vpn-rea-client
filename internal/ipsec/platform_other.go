//go:build !linux && !windows

package ipsec

import (
	"context"
	"errors"
)

type unsupportedBackend struct{}

func PlatformName() string                            { return "unsupported" }
func NewPlatformBackend(string, string) TunnelBackend { return unsupportedBackend{} }
func (unsupportedBackend) Platform() string           { return PlatformName() }
func (unsupportedBackend) Probe(context.Context) error {
	return errors.New("当前平台暂不支持 NC 内网隧道")
}
func (unsupportedBackend) Start(context.Context, Config) (StartResult, error) {
	return StartResult{}, errors.New("当前平台暂不支持 NC")
}
func (unsupportedBackend) Status(context.Context) (TunnelStatus, error) {
	return TunnelStatus{}, errors.New("当前平台暂不支持 NC")
}
func (unsupportedBackend) Stop(context.Context, Config) error { return nil }
