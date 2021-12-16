//go:build !android
// +build !android

package multiaddr

import "net"

func SetInterfaceAddrsGetter(getter InterfaceAddrsGetter) {}

type InterfaceAddr struct {
	Ip     []byte
	Prefix int
}

type InterfaceAddrsGetter interface {
	InterfaceAddrs() []InterfaceAddr
}

func InterfaceAddrs() (addrs []net.Addr, err error) {
	return net.InterfaceAddrs()
}
