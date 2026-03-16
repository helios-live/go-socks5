package socks5_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.ideatocode.tech/log"
	"go.ideatocode.tech/netplus"
	"go.ideatocode.tech/socks5/v2"
)

func TestClientCanDoSocksRequests(t *testing.T) {
	var l log.Logger
	if *withOutput {
		l = log.NewZero(os.Stderr)
	} else {
		l = log.NewZero(ioutil.Discard)
	}
	auth := func(ctx context.Context, uinfo socks5.UserPass, ip string) bool {
		return true
	}
	tunnel := func(ctx context.Context, i socks5.UserPass, ip string, c net.Conn, upstreamHost string, upstreamPort int, sc socks5.StatusCallback) {
		defer c.Close()

		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", upstreamHost, upstreamPort))
		if err != nil {
			sc("proxy-unreachable.status", socks5.StatusNetworkUnreachable)
			return
		}
		defer conn.Close()

		sc("succeeded.status", socks5.StatusSucceeded)

		p := netplus.NewPiper(l, 60*time.Second)

		p.Run(ctx, c, conn)
	}

	// assert.NoError(t, err, "Should not error")

	srv := &socks5.Server{
		AuthHandler:   auth,
		TunnelHandler: tunnel,
		Logger:        l,
		Timeout:       60 * time.Second,
		DumpData:      *withOutput,
	}

	ln, err := srv.Listen("127.0.0.1:0")
	assert.NoError(t, err, "Should not error")
	port := ln.Listener.Addr().(*net.TCPAddr).Port

	go func() {
		srv.Serve(ln)
	}()

	addr := fmt.Sprintf("127.0.0.1:%d", port)

	conn, err := net.Dial("tcp", addr)
	assert.NoError(t, err, "Should not error")

	// log.Error("Remove this and next line")
	cl := &socks5.Client{
		Auth: &socks5.UserPass{
			User: "bla",
			Pass: "bla",
		},
		Conn:     conn,
		DumpData: false,
		Timeout:  60 * time.Second,
	}
	socksConn, err := cl.Open(addr)
	assert.NoError(t, err, "Can not open proxy request")

	ctx := context.Background()
	// log.Debug("socks5 connect", host, port)
	err = socksConn.ConnectContext(ctx, "httpbin.org", 80)
	if err != nil {
		socksConn.Close()
		assert.NoError(t, err, "Can not connect to host")
	}

	// if resp != nil {
	// 	assert.Equal(t, resp.StatusCode, 200, "Expected status code to be 200")
	// }
}

func TestClientCanTimeoutDuringSocksRequests(t *testing.T) {
	var l log.Logger
	if *withOutput {
		l = log.NewZero(os.Stderr)
	} else {
		l = log.NewZero(ioutil.Discard)
	}
	auth := func(ctx context.Context, uinfo socks5.UserPass, ip string) bool {
		return true
	}
	tunnel := func(ctx context.Context, i socks5.UserPass, ip string, c net.Conn, upstreamHost string, upstreamPort int, sc socks5.StatusCallback) {
		defer c.Close()

		time.Sleep(1 * time.Second)
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", upstreamHost, upstreamPort))
		if err != nil {
			sc("proxy-unreachable.status", socks5.StatusNetworkUnreachable)
			return
		}
		defer conn.Close()

		sc("succeeded.status", socks5.StatusSucceeded)

		p := netplus.NewPiper(l, 60*time.Second)

		p.Run(ctx, c, conn)
	}

	// assert.NoError(t, err, "Should not error")

	srv := &socks5.Server{
		AuthHandler:   auth,
		TunnelHandler: tunnel,
		Logger:        l,
		Timeout:       60 * time.Second,
		DumpData:      *withOutput,
	}

	ln, err := srv.Listen("127.0.0.1:0")
	assert.NoError(t, err, "Should not error")
	port := ln.Listener.Addr().(*net.TCPAddr).Port

	go func() {
		srv.Serve(ln)
	}()

	addr := fmt.Sprintf("127.0.0.1:%d", port)

	conn, err := net.Dial("tcp", addr)
	assert.NoError(t, err, "Should not error")

	// log.Error("Remove this and next line")
	cl := &socks5.Client{
		Auth: &socks5.UserPass{
			User: "bla",
			Pass: "bla",
		},
		Conn:     conn,
		DumpData: false,
		Timeout:  60 * time.Second,
	}
	socksConn, err := cl.Open(addr)
	assert.NoError(t, err, "Can not open proxy request")

	ctx := context.Background()
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(500*time.Millisecond))
	defer cancel()
	// log.Debug("socks5 connect", host, port)
	err = socksConn.ConnectContext(ctx, "httpbin.org", 80)
	assert.Error(t, err, "Client does not timeout during connect")
	if err != nil {
		socksConn.Close()
	}

	// if resp != nil {
	// 	assert.Equal(t, resp.StatusCode, 200, "Expected status code to be 200")
	// }
}
