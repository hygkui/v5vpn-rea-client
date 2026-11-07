//go:build linux

package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type helperTestBackend struct {
	mu            sync.Mutex
	starts, stops int
	block         bool
	seen          Config
}

func (*helperTestBackend) Platform() string            { return "linux" }
func (*helperTestBackend) Probe(context.Context) error { return nil }
func (b *helperTestBackend) Start(ctx context.Context, c Config) (StartResult, error) {
	b.mu.Lock()
	b.starts++
	b.seen = c
	b.mu.Unlock()
	if b.block {
		<-ctx.Done()
		return StartResult{}, ctx.Err()
	}
	return StartResult{}, nil
}
func (*helperTestBackend) Status(context.Context) (TunnelStatus, error) {
	return TunnelStatus{Installed: true}, nil
}
func (b *helperTestBackend) Stop(context.Context, Config) error {
	b.mu.Lock()
	b.stops++
	b.mu.Unlock()
	return nil
}

func TestHelperRejectsUnknownFieldsWithoutStarting(t *testing.T) {
	b := &helperTestBackend{}
	for _, input := range []string{`{"op":"start","protocol":1,"path":"/etc/shadow"}`, `{"op":"exec","protocol":1}`, strings.Repeat("x", 65537)} {
		if err := ServeHelper(context.Background(), strings.NewReader(input+"\n"), io.Discard, b); err == nil {
			t.Fatal("unsafe request accepted")
		}
	}
	if b.starts != 0 {
		t.Fatal("invalid input mutated network")
	}
}

func TestHelperStopsOnParentEOF(t *testing.T) {
	b := &helperTestBackend{}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- ServeHelper(context.Background(), inR, outW, b); outW.Close() }()
	enc := json.NewEncoder(inW)
	dec := json.NewDecoder(outR)
	c := nativeProfile()
	if err := enc.Encode(helperRequest{Protocol: 1, Op: "start", Config: &c, Peer: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	var reply helperReply
	if err := dec.Decode(&reply); err != nil || !reply.OK {
		t.Fatalf("start reply: %+v %v", reply, err)
	}
	if err := enc.Encode(helperRequest{Protocol: 1, Op: "status"}); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(&reply); err != nil || !reply.Status.Installed {
		t.Fatal("status not installed", err)
	}
	inW.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("EOF did not tear down session")
	}
	if b.starts != 1 || b.stops != 1 {
		t.Fatalf("starts=%d stops=%d", b.starts, b.stops)
	}
	if b.seen.PSK != c.PSK {
		t.Fatal("dynamic PSK not handed to backend")
	}
	data, _ := json.Marshal(reply)
	if strings.Contains(string(data), c.PSK) {
		t.Fatal("PSK exposed in response")
	}
}

func TestHelperCancelsStartWhenParentDisappears(t *testing.T) {
	b := &helperTestBackend{block: true}
	r, w := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- ServeHelper(context.Background(), r, io.Discard, b) }()
	c := nativeProfile()
	json.NewEncoder(w).Encode(helperRequest{Protocol: 1, Op: "start", Config: &c, Peer: "192.0.2.1"})
	w.Close()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup ignored EOF")
	}
	if b.stops != 1 {
		t.Fatal("cancelled start was not cleaned")
	}
}
