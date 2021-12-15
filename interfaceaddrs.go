//go:build !android
// +build !android

package multiaddr

import "net"

func InterfaceAddrs() (addrs []net.Addr, err error) {
	return net.InterfaceAddrs()
}
