package oniontransport

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"github.com/cretz/bine/tor"
	"github.com/libp2p/go-libp2p-peer"
	"net"
	"strconv"
	"strings"

	tpt "github.com/libp2p/go-libp2p-transport"
	tptu "github.com/libp2p/go-libp2p-transport-upgrader"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multiaddr-net"
	"github.com/whyrusleeping/mafmt"
)

// isValidOnionMultiAddr is used to validate that a multiaddr
// is representing a Tor onion service
func isValidOnionMultiAddr(a ma.Multiaddr) bool {
	if len(a.Protocols()) != 1 {
		return false
	}

	// check for correct network type
	if a.Protocols()[0].Name != "onion" {
		return false
	}

	// split into onion address and port
	var (
		addr string
		err  error
	)
	addr, err = a.ValueForProtocol(ma.P_ONION3)
	if err != nil {
		addr, err = a.ValueForProtocol(ma.P_ONION)
		if err != nil {
			return false
		}
	}
	split := strings.Split(addr, ":")
	if len(split) != 2 {
		return false
	}

	// onion address without the ".onion" substring
	if len(split[0]) != 16 {
		fmt.Println(split[0])
		return false
	}
	_, err = base32.StdEncoding.DecodeString(strings.ToUpper(split[0]))
	if err != nil {
		return false
	}

	// onion port number
	i, err := strconv.Atoi(split[1])
	if err != nil {
		return false
	}
	if i >= 65536 || i < 1 {
		return false
	}

	return true
}

// OnionTransport implements go-libp2p-transport's Transport interface
type OnionTransport struct {
	tor           *tor.Tor
	dialOnlyOnion bool
	laddr         ma.Multiaddr

	// Connection upgrader for upgrading insecure stream connections to
	// secure multiplex connections.
	Upgrader *tptu.Upgrader
}

var _ tpt.Transport = &OnionTransport{}

// NewOnionTransport creates a new OnionTransport
func NewOnionTransport(tor *tor.Tor, dialOnionOnly bool, upgrader *tptu.Upgrader) (*OnionTransport, error) {
	o := OnionTransport{
		tor:           tor,
		dialOnlyOnion: dialOnionOnly,
		Upgrader:      upgrader,
	}
	return &o, nil
}

// OnionTransportC is a type alias for OnionTransport constructors, for use
// with libp2p.New
type OnionTransportC func(*tptu.Upgrader) (tpt.Transport, error)

// NewOnionTransportC is a convenience function that returns a function
// suitable for passing into libp2p.Transport for host configuration
func NewOnionTransportC(tor *tor.Tor, dialOnionOnly bool, upgrader *tptu.Upgrader) OnionTransportC {
	return func(upgrader *tptu.Upgrader) (tpt.Transport, error) {
		return NewOnionTransport(tor, dialOnionOnly, upgrader)
	}
}

// Dial dials a remote peer. It should try to reuse local listener
// addresses if possible but it may choose not to.
func (t *OnionTransport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (tpt.Conn, error) {
	dialer, err := t.tor.Dialer(context.Background(), nil)
	if err != nil {
		return nil, err
	}

	netaddr, err := manet.ToNetAddr(raddr)
	var onionAddress string
	if err != nil {
		onionAddress, err = raddr.ValueForProtocol(ma.P_ONION3)
		if err != nil {
			onionAddress, err = raddr.ValueForProtocol(ma.P_ONION)
			if err != nil {
				return nil, err
			}
		}
	}
	onionConn := OnionConn{
		transport: tpt.Transport(t),
		laddr:     t.laddr,
		raddr:     raddr,
	}
	if onionAddress != "" {
		split := strings.Split(onionAddress, ":")
		onionConn.Conn, err = dialer.Dial("tcp4", split[0]+".onion:"+split[1])
	} else {
		onionConn.Conn, err = dialer.Dial(netaddr.Network(), netaddr.String())
	}
	if err != nil {
		return nil, err
	}
	return t.Upgrader.UpgradeOutbound(ctx, t, &onionConn, p)
}

// Listen listens on the passed multiaddr.
func (t *OnionTransport) Listen(laddr ma.Multiaddr) (tpt.Listener, error) {
	// convert to net.Addr
	var (
		netaddr string
		err     error
	)
	netaddr, err = laddr.ValueForProtocol(ma.P_ONION3)
	if err != nil {
		netaddr, err = laddr.ValueForProtocol(ma.P_ONION)
		if err != nil {
			return nil, err
		}
	}

	// retreive onion service virtport
	addr := strings.Split(netaddr, ":")
	if len(addr) != 2 {
		return nil, fmt.Errorf("failed to parse onion address")
	}

	// convert port string to int
	port, err := strconv.Atoi(addr[1])
	if err != nil {
		return nil, fmt.Errorf("failed to convert onion service port to int")
	}

	listener := OnionListener{
		laddr:     laddr,
		Upgrader:  t.Upgrader,
		transport: t,
	}

	onion, err := t.tor.Listen(context.Background(), &tor.ListenConf{RemotePorts: []int{port}})
	if err != nil {
		return nil, fmt.Errorf("failed to create onion service: %v", err)
	}

	if onion.ID != addr[0] {
		return nil, errors.New("onion address does not match")
	}

	listener.listener = onion.LocalListener
	t.laddr = laddr

	return &listener, nil
}

// CanDial returns true if this transport knows how to dial the given
// multiaddr.
//
// Returning true does not guarantee that dialing this multiaddr will
// succeed. This function should *only* be used to preemptively filter
// out addresses that we can't dial.
func (t *OnionTransport) CanDial(a ma.Multiaddr) bool {
	if t.dialOnlyOnion {
		// only dial out on onion addresses
		return isValidOnionMultiAddr(a)
	} else {
		return isValidOnionMultiAddr(a) || mafmt.TCP.Matches(a)
	}
}

// Protocols returns the list of terminal protocols this transport can dial.
func (t *OnionTransport) Protocols() []int {
	if !t.dialOnlyOnion {
		return []int{ma.P_ONION, ma.P_TCP}
	} else {
		return []int{ma.P_ONION}
	}
}

// Proxy always returns false for the onion transport.
func (t *OnionTransport) Proxy() bool {
	return false
}

// OnionListener implements go-libp2p-transport's Listener interface
type OnionListener struct {
	laddr     ma.Multiaddr
	listener  net.Listener
	transport tpt.Transport
	Upgrader  *tptu.Upgrader
}

// Accept blocks until a connection is received returning
// go-libp2p-transport's Conn interface or an error if
// something went wrong
func (l *OnionListener) Accept() (tpt.Conn, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	raddr, err := manet.FromNetAddr(conn.RemoteAddr())
	if err != nil {
		return nil, err
	}
	onionConn := OnionConn{
		Conn:      conn,
		transport: l.transport,
		laddr:     l.laddr,
		raddr:     raddr,
	}
	return l.Upgrader.UpgradeInbound(context.Background(), l.transport, &onionConn)
}

// Close shuts down the listener
func (l *OnionListener) Close() error {
	return l.listener.Close()
}

// Addr returns the net.Addr interface which represents
// the local multiaddr we are listening on
func (l *OnionListener) Addr() net.Addr {
	netaddr, _ := manet.ToNetAddr(l.laddr)
	return netaddr
}

// Multiaddr returns the local multiaddr we are listening on
func (l *OnionListener) Multiaddr() ma.Multiaddr {
	return l.laddr
}

// OnionConn implement's go-libp2p-transport's Conn interface
type OnionConn struct {
	net.Conn
	transport tpt.Transport
	laddr     ma.Multiaddr
	raddr     ma.Multiaddr
}

// Transport returns the OnionTransport associated
// with this OnionConn
func (c *OnionConn) Transport() tpt.Transport {
	return c.transport
}

// LocalMultiaddr returns the local multiaddr for this connection
func (c *OnionConn) LocalMultiaddr() ma.Multiaddr {
	return c.laddr
}

// RemoteMultiaddr returns the remote multiaddr for this connection
func (c *OnionConn) RemoteMultiaddr() ma.Multiaddr {
	return c.raddr
}
