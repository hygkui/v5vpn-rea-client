package ipsec

import "context"

type TunnelStatus struct {
	Installed bool   `json:"installed"`
	InBytes   uint64 `json:"rxBytes"`
	OutBytes  uint64 `json:"txBytes"`
}
type StartResult struct {
	Message  string
	Warnings []string
	Gateway  string
}
type TunnelBackend interface {
	Platform() string
	Probe(context.Context) error
	Start(context.Context, Config) (StartResult, error)
	Status(context.Context) (TunnelStatus, error)
	Stop(context.Context, Config) error
}
