package multiaddr

import (
	"fmt"
	"net"
	"sync"
)

var lock = sync.Mutex{}
var interfaceGetter InterfaceAddrGetter

func SetInterfaceAddrGetter(getter InterfaceAddrGetter) {
	lock.Lock()
	defer lock.Unlock()
	interfaceGetter = getter
}

type InterfaceAddr struct {
	Ip     []byte
	Prefix int
}

type InterfaceAddrGetter interface {
	Interfaces() []InterfaceAddr
}

func maskFromPrefix(prefix, base int) net.IPMask {
	buf := make([]byte, base/8, base/8)
	for i := 0; i < prefix/8; i++ {
		buf[i] = 0xff
	}
	if prefix != base {
		buf[prefix/8] = ((1 << prefix % 8) - 1) << (8 - prefix%8)
	}
	return buf
}

func ipV6MaskFromPrefix(prefix int) net.IPMask {
	return maskFromPrefix(prefix, 128)
}

func ipV4MaskFromPrefix(prefix int) net.IPMask {
	return maskFromPrefix(prefix, 32)
}

func InterfaceAddrs() (addrs []net.Addr, err error) {
	lock.Lock()
	if interfaceGetter == nil {
		lock.Unlock()
		return nil, fmt.Errorf("interface getter not set for Android")
	}
	lock.Unlock()
	unmaskedAddrs := interfaceGetter.Interfaces()
	for _, addr := range unmaskedAddrs {
		var mask []byte
		if len(addr.Ip) == 4 {
			mask = ipV4MaskFromPrefix(addr.Prefix)
		} else {
			mask = ipV6MaskFromPrefix(addr.Prefix)
		}
		addrs = append(addrs, &net.IPNet{
			IP:   addr.Ip,
			Mask: mask,
		})
	}
	return addrs, nil
}
