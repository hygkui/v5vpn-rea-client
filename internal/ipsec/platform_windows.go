//go:build windows

package ipsec

func PlatformName() string { return "windows" }
func NewPlatformBackend(confPath, _ string) TunnelBackend {
	return NewWindowsBackend(NewManager(confPath), nil)
}
