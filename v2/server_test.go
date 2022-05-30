package socks5_test

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.ideatocode.tech/log"
	"go.ideatocode.tech/netplus"
	"go.ideatocode.tech/socks5/v2"
	gproxy "golang.org/x/net/proxy"
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
func proxiedRequest(t *testing.T, proxyStr, urlStr string) (*http.Response, error) {

	//creating the proxyURL
	// proxyStr := "http://localhost:7000"
	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		assert.NoError(t, err, "Should not error: proxyURL")
		return nil, err
	}

	//creating the URL to be loaded through the proxy
	// urlStr := "http://httpbin.org/get"
	url, err := url.Parse(urlStr)
	if err != nil {
		assert.NoError(t, err, "Should not error: url.Parse")
		return nil, err
	}

	var transport *http.Transport
	if proxyURL.Scheme == "http" {

		//adding the proxy settings to the Transport object
		transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}

	} else {
		baseDialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		var auth *gproxy.Auth
		if proxyURL.User.String() != "" {
			pass, _ := proxyURL.User.Password()
			auth = &gproxy.Auth{
				User:     proxyURL.User.Username(),
				Password: pass,
			}

			// this case should never happen in real life,
			// this is when we tell the server that we have a user/pass
			// but don't actually have them
			if proxyURL.User.Username() == "invalid" {
				auth = &gproxy.Auth{
					User:     "",
					Password: "",
				}
			}
		} else {
			auth = nil
		}
		dialSocksProxy, err := gproxy.SOCKS5("tcp", proxyURL.Host, auth, baseDialer)
		assert.NoError(t, err, "Should not error")

		if contextDialer, ok := dialSocksProxy.(gproxy.ContextDialer); ok {
			dialContext := contextDialer.DialContext
			transport = &http.Transport{
				DialContext: dialContext,
			}
		} else {
			t.Fatal("Could not initialize socks5 request")
		}
	}

	//adding the Transport object to the http Client
	client := &http.Client{
		Transport: transport,
	}

	//generating the HTTP GET request
	request, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		assert.NoError(t, err, "Should not error: http.NewRequest")
		return nil, err
	}

	//calling the URL
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	return response, err
}
