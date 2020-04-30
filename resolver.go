package oniontransport

import (
	"context"
	"errors"
	madns "github.com/multiformats/go-multiaddr-dns"
	"net"
)

type torBackend struct {
	proxy string
}

// NewTorResover returns a no madns.Resolver that will resolve
// IP addresses over Tor.
func NewTorResover(proxy string) *madns.Resolver {
	return &madns.Resolver{
		Backend: &torBackend{
			proxy: proxy,
		},
	}
}

// LookupIPAddr resolves hostnames over Tor and returns an IPv4 address.
func (r *torBackend) LookupIPAddr(ctx context.Context, name string) ([]net.IPAddr, error) {
	type resp struct {
		Addrs []net.IP
		Err   error
	}
	out := make(chan *resp)
	go func() {
		addrs, err := TorLookupIP(name, r.proxy)
		out <- &resp{addrs, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-out:
		if r.Err != nil {
			return nil, r.Err
		}
		addrs := make([]net.IPAddr, 0, len(r.Addrs))
		for _, addr := range r.Addrs {
			addrs = append(addrs, net.IPAddr{
				IP: addr,
			})
		}
		return addrs, nil
	}
}

// TODO: Figure out if it is possible to resolve TXT records over Tor.
func (r *torBackend) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return nil, errors.New("resolving TXT records over Tor not yet supported")
}
