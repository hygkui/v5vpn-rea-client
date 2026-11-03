//go:build linux && !ipsectest

package ipsec

func PlatformName() string                                   { return "linux" }
func NewPlatformBackend(confPath, peer string) TunnelBackend { return NewLinuxBackend(confPath, peer) }
