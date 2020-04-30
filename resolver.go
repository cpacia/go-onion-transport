package oniontransport

import (
	"context"
	madns "github.com/multiformats/go-multiaddr-dns"
	"net"
	"time"
)

type torBackend struct {
	proxy string
}

// NewTorResover returns a no madns.Resolver that will resolve
// IP addresses over Tor.
//
// TODO: This does not seem to work for TXT records. Look into if
// Tor can resolve TXT records.
func NewTorResover(proxy string) *madns.Resolver {
	return &madns.Resolver{
		Backend: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * time.Duration(10000),
				}
				return d.DialContext(ctx, network, proxy)
			},
		},
	}
}
