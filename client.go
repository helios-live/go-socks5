package socks5 // import go.ideatocode.tech/socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"go.ideatocode.tech/debug"
	"go.ideatocode.tech/netplus"
)

// Client is the Socks5Proxy client
type Client struct {
	// AuthType      string
	// Addr          string
	Timeout time.Duration
	Auth    *UserPass
	// Conn if is set, the socks uses that connection instead of dialing itself
	Conn     net.Conn
	DumpData bool
}

// SocksClientConn is a wrapper for net.Conn
type SocksClientConn struct {
	net.Conn
	isClosed bool
}

// Close closes the socks5clientConn only once
func (cc *SocksClientConn) Close() error {
	if cc.isClosed {
		return nil
	}
	cc.isClosed = true
	return cc.Conn.Close()
}

// Open opens a Socks5 tunnel to addr
func (c *Client) Open(addr string) (cc *SocksClientConn, err error) {

	conn := c.Conn
	c.Conn.SetDeadline(time.Now().Add(c.Timeout))

	if c.DumpData {
		conn = &debug.PrinterConn{Conn: conn, Prefix: "(socksclient):"}
	}
	conn = &netplus.CounterConn{Conn: conn}

	err = c.performHandshake(conn)
	if err != nil {
		return nil, err
	}
	c.Conn.SetDeadline(time.Time{})
	return &SocksClientConn{Conn: conn}, err
}

// Connect sends the connection request
func (cc *SocksClientConn) Connect(addr string, port int) error {
	var atyp byte
	var addrb []byte
	ip := net.ParseIP(addr)
	if ip == nil {
		atyp = 0x03
		addrb = append([]byte{byte(len(addr))}, []byte(addr)...)
	} else if ip.To4() == nil {
		atyp = 0x04
		addrb = []byte(ip)
	} else {
		atyp = 0x01
		addrb = []byte(ip.To4())
	}
	portb := make([]byte, 2)
	binary.BigEndian.PutUint16(portb, uint16(port))
	x := requestBinHeader{
		ver:  0x05,
		cmd:  0x01,
		rsv:  0x00,
		atyp: atyp,
		addr: &addrb,
		port: portb,
	}
	_, err := x.WriteTo(cc)
	if err != nil {
		cc.Close()
		return err
	}

	// read response status
	_, err = readReqHeader(cc, false)
	if err != nil {
		cc.Close()
		return err
	}
	return nil
}

func (c *Client) performHandshake(conn net.Conn) (err error) {
	if c.Auth == nil {
		_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	} else {
		_, err = conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
	}
	if err != nil {
		return err
	}

	buf := make([]byte, 2)
	n, err := conn.Read(buf)
	if err != nil || n != 2 {
		return err
	}
	if buf[1] == 0x00 {
		return nil
	}
	if c.Auth == nil {
		return errors.New("No supported auth methods")
	}
	if buf[1] == 0x02 {
		return c.performAuth(conn)
	}
	return errors.New("No supported auth methods")

}

func (c *Client) performAuth(conn net.Conn) error {
	h := &AuthHeader{
		Bin: authBinHeader{
			ver:    0x01,
			ulen:   byte(len(c.Auth.User)),
			uname:  []byte(c.Auth.User),
			plen:   byte(len(c.Auth.Pass)),
			passwd: []byte(c.Auth.Pass),
		},
	}

	_, err := h.Bin.WriteTo(conn)
	if err != nil {
		return err
	}
	buf := make([]byte, 2)

	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if n != 2 {
		return errors.New("performAuthResponse only 1 byte")
	}
	// return successful
	if buf[1] == 0x00 {
		return nil
	}

	return fmt.Errorf("performAuthResponse invalid user/pass: %X", buf[1:])
}
