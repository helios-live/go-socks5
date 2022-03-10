package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// RequestHeader holds the header of the socks5 connection request
type RequestHeader struct {
	Bin struct {
		ver  byte
		cmd  byte
		rsv  byte
		atyp byte
		addr *[]byte
		port []byte
	}

	Port int
	Addr string
}

type requestBinHeader struct {
	ver  byte
	cmd  byte
	rsv  byte
	atyp byte
	addr *[]byte
	port []byte
}

// AuthHeader is used to perform User/Password socks5 authentication
type AuthHeader struct {
	Bin      authBinHeader
	Username string
	Password string
}
type authBinHeader struct {
	ver    byte
	ulen   byte
	uname  []byte
	plen   byte
	passwd []byte
}

// WriteTo writes the header to w
func (h *authBinHeader) WriteTo(w io.Writer) (int64, error) {
	buf := []byte{h.ver, h.ulen}
	buf = append(buf, h.uname...)
	buf = append(buf, h.plen)
	buf = append(buf, h.passwd...)
	n, err := w.Write(buf)
	return int64(n), err
}

// WriteTo writes the header to w
func (h *requestBinHeader) WriteTo(w io.Writer) (int64, error) {
	buf := []byte{h.ver, h.cmd, h.rsv, h.atyp}
	buf = append(buf, *h.addr...)
	buf = append(buf, h.port...)
	n, err := w.Write(buf)
	return int64(n), err
}

func readReqHeader(c net.Conn, outgoing bool) (*RequestHeader, error) {
	rh := RequestHeader{}

	h1 := make([]byte, 4)
	n, err := c.Read(h1)
	if n != 4 || err != nil {
		return nil, err
	}
	cmd := h1[1]
	rh.Bin.ver = h1[0]
	rh.Bin.cmd = h1[1]

	atyp := h1[3]
	rh.Bin.atyp = h1[3]
	var addr string
	switch atyp {
	// if ipv4
	case 0x01:
		var b net.IP
		b = make([]byte, 4)
		n, err = c.Read(b)
		if n != 4 || err != nil {
			return nil, err
		}
		bn := []byte(b)
		rh.Bin.addr = &bn
		addr = b.String()
	// if domain
	case 0x03:
		addrl := make([]byte, 1)
		n, err = c.Read(addrl)
		if n != 1 || err != nil {
			return nil, err
		}
		addrb := make([]byte, int(addrl[0])+1)
		addrb[0] = addrl[0]
		n, err = c.Read(addrb[1:])
		if n != int(addrl[0]) || err != nil {
			return nil, err
		}
		rh.Bin.addr = &addrb
		addr = string(addrb[1:])

	// if ipv6
	case 0x04:
		var b net.IP
		b = make([]byte, 16)
		n, err = c.Read(b)
		if n != 16 || err != nil {
			return nil, err
		}
		bn := []byte(b)
		rh.Bin.addr = &bn
		addr = b.String()
	}

	portb := make([]byte, 2)
	rh.Bin.port = portb
	n, err = c.Read(portb)
	if n != 2 || err != nil {
		return nil, err
	}
	port := binary.BigEndian.Uint16(portb)
	rh.Addr = addr
	rh.Port = int(port)

	// only connect allowed
	if outgoing && cmd != 0x01 {
		return nil, fmt.Errorf("Only Connect: %X, %s:%d", cmd, addr, rh.Port)
	}

	if !outgoing && cmd != 0x00 {
		return nil, fmt.Errorf("Server refused: %X, %s:%d", cmd, addr, rh.Port)
	}

	return &rh, nil
}
