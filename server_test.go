package socks5_test

import (
	"context"
	"flag"
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

var withOutput = flag.Bool("withOutput", false, "When set to true some tests will turn on output")

func TestCanDoSocksRequests(t *testing.T) {
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

	resp, err := proxiedRequest(t, fmt.Sprintf("socks5://abc:def@127.0.0.1:%d", port), "http://httpbin.org:80/get")
	assert.NoError(t, err, "Should not error")

	if resp != nil {
		assert.Equal(t, resp.StatusCode, 200, "Expected status code to be 200")
	}
}

func TestCanDoSocksRequestWithEmptyUserPass(t *testing.T) {
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

	resp, err := proxiedRequest(t, fmt.Sprintf("socks5://127.0.0.1:%d", port), "http://httpbin.org:80/get")
	assert.NoError(t, err, "Should not error")

	if resp != nil {
		assert.Equal(t, resp.StatusCode, 200, "Expected status code to be 200")
	}
}

func TestCantDoSocksRequestWithNotSetUserPass(t *testing.T) {
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

	resp, err := proxiedRequest(t, fmt.Sprintf("socks5://invalid@127.0.0.1:%d", port), "http://httpbin.org:80/get")
	assert.Error(t, err, "Should always error")

	if resp != nil {
		assert.Equal(t, resp.StatusCode, 200, "Expected status code to be 200")
	}
}
