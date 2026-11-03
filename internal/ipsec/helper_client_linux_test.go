//go:build linux

package ipsec

import (
	"context"
	"io"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func testHelperProcess(b *helperTestBackend) *helperProcess {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan struct{})
	var err error
	go func() { err = ServeHelper(context.Background(), inR, outW, b); outW.Close(); close(done) }()
	return &helperProcess{in: inW, out: outR, done: done, waitErr: func() error { return err }, cancelAuth: func() {}}
}

func TestLinuxBackendKeepsHelperAfterStartupContextEnds(t *testing.T) {
	b := &helperTestBackend{}
	client := newLinuxBackend("192.0.2.1")
	client.check = func(context.Context) error { return nil }
	client.launch = func() (*helperProcess, error) { return testHelperProcess(b), nil }
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := client.Start(ctx, nativeProfile()); err != nil {
		t.Fatal(err)
	}
	cancel()
	status, err := client.Status(context.Background())
	if err != nil || !status.Installed {
		t.Fatal("successful startup cancellation killed live helper", err)
	}
	if err := client.Stop(context.Background(), nativeProfile()); err != nil {
		t.Fatal(err)
	}
	if b.stops != 1 {
		t.Fatal("stop did not clean helper")
	}
}

func TestLinuxBackendCancelStartupClosesSession(t *testing.T) {
	b := &helperTestBackend{block: true}
	client := newLinuxBackend("192.0.2.1")
	var p *helperProcess
	var mu sync.Mutex
	client.launch = func() (*helperProcess, error) { mu.Lock(); defer mu.Unlock(); p = testHelperProcess(b); return p, nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := client.Start(ctx, nativeProfile()); done <- err }()
	for {
		mu.Lock()
		ready := p != nil
		mu.Unlock()
		if ready {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled startup succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("startup did not cancel")
	}
	if err := client.Stop(context.Background(), nativeProfile()); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxBackendRejectsMissingAuthenticatedPeerBeforeAuthorization(t *testing.T) {
	for _, peer := range []string{"", "127.0.0.1", "not-an-ip"} {
		client := newLinuxBackend(peer)
		client.launch = func() (*helperProcess, error) {
			t.Fatal("launched helper without authenticated IPv4 peer")
			return nil, nil
		}
		if _, err := client.Start(context.Background(), nativeProfile()); err == nil {
			t.Fatal("invalid peer accepted")
		}
	}
}

func TestLinuxBackendReceivesReplyBeforeHelperExit(t *testing.T) {
	b := newLinuxBackend("192.0.2.1")
	b.launch = func() (*helperProcess, error) {
		return startHelperProcess(exec.Command("/bin/sh", "-c", `read request; printf '{"protocol":1,"ok":false,"error":"fixture rejected"}\n'; exit 1`))
	}
	if _, err := b.Start(context.Background(), nativeProfile()); err == nil || !strings.Contains(err.Error(), "fixture rejected") {
		t.Fatalf("exit discarded the final reply: %v", err)
	}
}
