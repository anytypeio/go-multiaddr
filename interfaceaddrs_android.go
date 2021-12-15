package multiaddr

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

type Ifreq struct {
	Name [16]byte
	Data [16]byte
}

func ioctl(fd, op, arg uintptr) error {
	_, _, ep := syscall.Syscall(syscall.SYS_IOCTL, fd, op, arg)
	if ep != 0 {
		return syscall.Errno(ep)
	}
	return nil
}

func maskFromPrefix(prefix int) net.IPMask {
	buf := make([]byte, 16, 16)
	for i := 0; i < prefix/8; i++ {
		buf[i] = 0xff
	}
	if prefix != 128 {
		buf[prefix/8] = (1 << (prefix % 8)) - 1
		// converting to big endian notation used in network protocols
		buf[prefix/8] = ((buf[prefix/8] >> 4) & 0xf) | ((buf[prefix/8] & 0xf) << 4)
	}
	return buf
}

func parseIPV6(addrEntry string) (ipNet *net.IPNet, netInterface string, err error) {
	// The format looks something like this "fe800000000000000000000000000000 407 40 20 80    wlan0"
	split := strings.Split(addrEntry, " ")
	i := 0
	for _, el := range split {
		if el != "" {
			split[i] = el
			i++
		}
	}
	split = split[:i]
	if len(split) != 6 {
		err = fmt.Errorf("incorrect format of address entry, has %d components instead of 6", len(split))
		return
	}
	addr := split[0]
	addrBytes := make([]byte, 16, 16)
	if len(addr) != 32 {
		err = fmt.Errorf("incorrect ipv6 addr size")
		return
	}
	var value int64
	for i := 0; i < 16; i++ {
		value, err = strconv.ParseInt(addr[2*i:2*i+2], 16, 16)
		if err != nil {
			return
		}
		addrBytes[i] = uint8(value)
	}
	prefix64, err := strconv.ParseInt(split[2], 16, 16)
	if err != nil {
		return
	}
	return &net.IPNet{
		IP:   addrBytes,
		Mask: maskFromPrefix(int(prefix64)),
	}, split[len(split)-1], nil
}

func callIfReqIP(netInterface string, sig uintptr) (res []byte, err error) {
	req := Ifreq{}
	copy(req.Name[:], netInterface)
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return
	}
	err = ioctl(uintptr(sock), sig, uintptr(unsafe.Pointer(&req)))
	if err != nil {
		return
	}
	res = make([]byte, 4, 4)
	copy(res[:], req.Data[4:8])
	return
}

func getIPV4(netInterface string) (ipNet *net.IPNet, err error) {
	ipBuf, err := callIfReqIP(netInterface, syscall.SIOCGIFADDR)
	if err != nil {
		return
	}
	ipMaskBuf, err := callIfReqIP(netInterface, syscall.SIOCGIFNETMASK)
	if err != nil {
		return
	}
	return &net.IPNet{
		IP:   net.IPv4(ipBuf[0], ipBuf[1], ipBuf[2], ipBuf[3]),
		Mask: net.IPv4Mask(ipMaskBuf[0], ipMaskBuf[1], ipMaskBuf[2], ipMaskBuf[3]),
	}, nil
}

func listAllFiles(folderName string) ([]string, error) {
	files, err := ioutil.ReadDir(folderName)
	if err != nil {
		return nil, err
	}

	var filenames []string
	for _, file := range files {
		filenames = append(filenames, file.Name())
	}
	return filenames, nil
}

func readLines(path string) ([]string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	rd := bufio.NewReader(f)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if len(line) > 1 {
			lines = append(lines, line[:len(line)-1])
		}
	}
	return lines, nil
}

func sysSocket(family, sotype, proto int) (int, error) {
	syscall.ForkLock.RLock()
	s, err := syscall.Socket(family, sotype, proto)
	if err == nil {
		syscall.CloseOnExec(s)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return -1, os.NewSyscallError("socket", err)
	}
	if err = syscall.SetNonblock(s, true); err != nil {
		syscall.Close(s)
		return -1, os.NewSyscallError("setnonblock", err)
	}
	return s, nil
}

func InterfaceAddrs() (addrs []net.Addr, err error) {
	names, err := listAllFiles("/sys/class/net")
	if err != nil {
		return
	}
	ipV6Lines, err := readLines("/proc/net/if_inet6")
	if err != nil {
		return
	}
	ipV6Map := make(map[string][]*net.IPNet)
	for _, line := range ipV6Lines {
		ip, iface, err := parseIPV6(line)
		if err != nil {
			return nil, err
		}
		ipV6Map[iface] = append(ipV6Map[iface], ip)
	}

	for _, name := range names {
		if ips, exists := ipV6Map[name]; exists {
			for _, ip := range ips {
				addrs = append(addrs, ip)
			}
		}
		ipV4, err := getIPV4(name)
		if err != nil {
			if strings.Contains(err.Error(), "cannot assign requested address") {
				continue
			}
			return nil, err
		}
		addrs = append(addrs, ipV4)
	}
	return addrs, nil
}
