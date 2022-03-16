package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	dbg "runtime/debug"

	"github.com/ideatocode/go/debugging"
	"github.com/ideatocode/go/log"
	"github.com/ideatocode/go/netplus"
)

// 2.0.0

// Status is used to send Replies to socks client
type Status byte

// StatusCallback is used to reply to the socks client the status of the connection request
type StatusCallback func(string, Status)

var (
	// 	// StatusNotAllowed is sent when the connection is not allowed
	// 	StatusNotAllowed Status = []byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00}
	// 	// StatusSucceeded is sent when the connection is successful
	// 	StatusSucceeded Status = []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00}
	// 	// StatusBadGateway is sent when the proxy could not connect
	// 	StatusBadGateway Status = []byte{0x05, 0x04, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00}

	// StatusSucceeded is sent when the connection is successful
	StatusSucceeded Status = Status(0x00)

	// StatusGeneralFailure is sent when the connection is successful
	StatusGeneralFailure Status = Status(0x01)

	// StatusConnectionNotAllowedByRuleset is sent when the connection is successful
	StatusConnectionNotAllowedByRuleset Status = Status(0x02)

	// StatusNetworkUnreachable is sent when the connection is successful
	StatusNetworkUnreachable Status = Status(0x03)

	// StatusHostUnreachable is sent when the connection is successful
	StatusHostUnreachable Status = Status(0x04)

	// StatusConnectionRefused is sent when the connection is successful
	StatusConnectionRefused Status = Status(0x05)

	// StatusTTLExpired is sent when the connection is successful
	StatusTTLExpired Status = Status(0x06)

	// StatusCommandNotSupported is sent when the connection is successful
	StatusCommandNotSupported Status = Status(0x07)

	// StatusAddressTypeNotSupported is sent when the connection is successful
	StatusAddressTypeNotSupported Status = Status(0x08)

	statusHostUnreachable = customError("host-unreachable.status", StatusHostUnreachable)
	statusSucceeded       = customError("succeeded.status", StatusSucceeded)
)

type socksConn struct {
	net.Conn
	isClosed bool
}

// UserPass is the user and password the client used to authenticate
type UserPass struct {
	User string
	Pass string
}

// Server is the Socks5Proxy server
type Server struct {
	Addr          string
	AuthHandler   func(ctx context.Context, uinfo UserPass, ip string) bool
	TunnelHandler func(ctx context.Context, uinfo UserPass, ip string, c net.Conn, upstreamHost string, upstreamPort int, sc StatusCallback)
	Timeout       time.Duration
	listener      net.Listener
	Logger        log.Logger
	DumpData      bool
}

func (s socksConn) Close() error {
	if s.isClosed {
		return errors.New("Already closed")
	}
	return s.Conn.Close()
}

// ListenAndServe listens to and serves connections, it blocks
func (ss *Server) ListenAndServe() error {
	ln, err := ss.Listen(ss.Addr)
	if err != nil {
		return err
	}

	return ss.Serve(ln)
}

// Listen listens on an address
func (ss *Server) Listen(addr string) (*netplus.CounterListener, error) {

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	cl := netplus.CounterListener{Listener: l}
	return &cl, nil
}

// Serve serves connection on an existing listener
func (ss *Server) Serve(list net.Listener) error {

	ss.listener = list
	ss.Logger.Debug("[Socks]Listening on", list.Addr())

	for {
		rw, err := list.Accept()

		if err != nil {
			return err
		}
		ss.Logger.Debug("[Socks]New connection from", rw.RemoteAddr(), "to", ss.listener.Addr())

		sc := socksConn{rw, false}
		cc := &netplus.CounterConn{Conn: sc, Upstream: 0, Downstream: 0}
		if ss.DumpData {
			cp := &debugging.PrinterConn{Conn: sc}
			cc = &netplus.CounterConn{Conn: cp, Upstream: 0, Downstream: 0}
		}
		ctx := context.Background()
		go ss.serve(ctx, cc)
	}
}

// Close closes the listener
// TODO: also close exising connections
func (ss *Server) Close() {
	if ss.listener != nil {
		ss.listener.Close()
	}
}

func (ss *Server) serve(ctx context.Context, c net.Conn) {

	// set a deadline
	c.SetDeadline(time.Now().Add(ss.Timeout))

	defer func() {
		if r := recover(); r != nil {
			dbg.PrintStack()
			fmt.Println(fmt.Sprintf("[Socks](%s)", ss.Addr), "Recovered from connection failed in f", r)
		}
	}()

	uinfo, ip, err := ss.performHandshake(ctx, c)
	if err != nil {
		ss.Logger.Debug("[Socks] handshake error:", err)
		return
	}

	rh, err := readReqHeader(c, true)
	if rh == nil || err != nil {
		ss.Logger.Debug(fmt.Sprintf("[Socks](%s) e: Failed to ReadReqHeader, %s", ss.Addr, err))
		c.Close()
		return
	}

	c.SetDeadline(time.Time{}) // remove the deadline

	if ss.TunnelHandler != nil {
		ss.TunnelHandler(ctx, *uinfo, ip, c, rh.Addr, rh.Port, func(domain string, st Status) {
			c.Write(customError(domain, st))
			if byte(st) != byte(StatusSucceeded) {
				c.Close()
			}
		})
	} else {
		addr := net.JoinHostPort(rh.Addr, fmt.Sprintf("%d", rh.Port))
		// dc, err := net.DialTimeout("tcp", addr, ss.Timeout)
		var d net.Dialer
		dialctx, cancel := context.WithTimeout(ctx, ss.Timeout)
		dc, err := d.DialContext(dialctx, "tcp", addr)
		defer cancel()

		if err != nil {
			ss.Logger.Debug(fmt.Sprintf("[Socks](%s) e: Failed to Dial %s, %s", ss.Addr, addr, err))
			c.Write(statusHostUnreachable)
			return
		}
		c.Write(statusSucceeded)
		go io.Copy(c, dc)
		io.Copy(dc, c)
	}
	c.Close()
}

func (ss *Server) performHandshake(ctx context.Context, c net.Conn) (uinfo *UserPass, ip string, err error) {

	// read socks ver
	b1 := make([]byte, 1)
	n, err := c.Read(b1)
	if n != 1 || err != nil || b1[0] != 0x05 {
		c.Close()
		return nil, "", fmt.Errorf("[Socks](%s) e: socksver, %s", ss.Addr, err)
	}

	// read num methods
	b1 = make([]byte, 1)
	n, err = c.Read(b1)
	if n != 1 || err != nil {
		c.Close()
		return nil, "", fmt.Errorf("[Socks](%s) e: numm n, %s", ss.Addr, err)
	}

	num := int(b1[0])
	methodsb := make([]byte, num)

	n, err = c.Read(methodsb)

	// error reading num methods
	if err != nil || n != num {

		return nil, "", fmt.Errorf("[Socks](%s) e: numm, %s", ss.Addr, err)
	}

	methods := fmt.Sprintf("%d methods:", num)
	hasMethod := false
	for i := 0; i < n; i++ {
		methods = fmt.Sprintf("%s %d", methods, methodsb[i])
		// user & pass auth
		if methodsb[i] == 0x02 {
			hasMethod = true
		}
	}

	if hasMethod {
		// auth pass
		c.Write([]byte{0x05, 0x02})
		uinfo, err = getSocksPassAuth(c)
		if uinfo == nil || err != nil {
			c.Write([]byte{0x01, 0xff})
			c.Close()
			return nil, "", fmt.Errorf("[Socks](%s) e: Failed to get authentication: %s", ss.Addr, err)
		}
	}

	ip = strings.Split(c.RemoteAddr().String(), ":")[0]
	if ss.AuthHandler != nil {
		allowed := ss.AuthHandler(ctx, *uinfo, ip)
		if !allowed {
			c.Write([]byte{0x05, 0xff})
			c.Close()
			return uinfo, ip, fmt.Errorf("[Socks](%s) e: refused by authhandler: %s", ss.Addr, err)
		}
	}
	// write success
	c.Write([]byte{0x01, 0x00})
	return uinfo, ip, nil
}

func getSocksPassAuth(c net.Conn) (*UserPass, error) {

	h1 := make([]byte, 2)
	n, err := c.Read(h1)
	if n != 2 || err != nil {
		return nil, err
	}

	uname := make([]byte, h1[1])
	n, err = c.Read(uname)

	if n != int(h1[1]) || err != nil {
		return nil, err
	}
	plen := make([]byte, 1)
	n, err = c.Read(plen)

	if n != 1 || err != nil {
		return nil, err
	}
	passwd := make([]byte, plen[0])
	n, err = c.Read(passwd)

	if n != int(plen[0]) || err != nil {
		return nil, err
	}
	return &UserPass{
		User: string(uname),
		Pass: string(passwd),
	}, nil

}

// socksDom turns a string into a byte array for socks [len, dom]
func socksDom(dom string) []byte {
	d := []byte(dom)
	return append([]byte{uint8(len(d))}, d...)
}

func customError(dom string, status Status) []byte {
	domB := socksDom(dom)

	return append(append([]byte{0x05, byte(status), 0x00, 0x03}, domB...), []byte{0x00, 0x00}...)
}
