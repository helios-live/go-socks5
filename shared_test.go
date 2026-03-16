package socks5_test

import (
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	gproxy "golang.org/x/net/proxy"
)

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
