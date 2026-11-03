package ipsec

import (
	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
	"testing"
)

func TestFromNCRejectsExplicitUnsupportedNegotiation(t *testing.T) {
	for _, mutate := range []func(*protocol.NCResource){func(n *protocol.NCResource) { n.IKE.Version = "v2" }, func(n *protocol.NCResource) { n.IKE.Exchange.Mode = "aggressive" }, func(n *protocol.NCResource) { n.IKE.Client.IDType = "ipv4" }} {
		n := sampleNC()
		mutate(&n)
		if _, err := FromNC([]protocol.NCResource{n}); err == nil {
			t.Fatal("unsupported NC negotiation silently treated as IKEv1 main/key_id")
		}
	}
}
