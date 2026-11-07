//go:build linux

package main

import (
	"context"
	"github.com/hygkui/v5vpn-rea-client/internal/ipsec"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTargetTLSRequiresExplicitOptIn(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer s.Close()
	if _, err := probeHTTP(context.Background(), s.URL, false); err == nil {
		t.Fatal("untrusted target certificate accepted without opt-in")
	}
	if code, err := probeHTTP(context.Background(), s.URL, true); err != nil || code != http.StatusOK {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func TestTargetRedirectDoesNotReachUnprotectedHost(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid/", http.StatusFound)
	}))
	defer s.Close()
	if _, err := probeHTTP(context.Background(), s.URL, false); err == nil {
		t.Fatal("redirect outside target host accepted")
	}
}

func TestFlowRequiresNewBidirectionalESPBytes(t *testing.T) {
	before := ipsec.NativeProbeStatus{Installed: true, InBytes: 100, OutBytes: 100}
	if err := verifyFlow(before, before, http.StatusOK); err == nil {
		t.Fatal("old unrelated traffic accepted")
	}
	after := ipsec.NativeProbeStatus{Installed: true, InBytes: 200, OutBytes: 300}
	if err := verifyFlow(before, after, http.StatusOK); err != nil {
		t.Fatal(err)
	}
	after.Installed = false
	if err := verifyFlow(before, after, http.StatusOK); err == nil {
		t.Fatal("missing SA accepted")
	}
}
