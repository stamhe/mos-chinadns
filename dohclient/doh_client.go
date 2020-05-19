//     Copyright (C) 2020, IrineSistiana
//
//     This file is part of mos-chinadns.
//
//     mos-chinadns is free software: you can redistribute it and/or modify
//     it under the terms of the GNU General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     mos-chinadns is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU General Public License for more details.
//
//     You should have received a copy of the GNU General Public License
//     along with this program.  If not, see <https://www.gnu.org/licenses/>.

package dohclient

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/IrineSistiana/mos-chinadns/utils"

	"github.com/IrineSistiana/mos-chinadns/bufpool"

	"github.com/sirupsen/logrus"

	"github.com/miekg/dns"

	"github.com/valyala/fasthttp"
	"golang.org/x/net/http2"
)

// err
var (
	ErrMsgTooLarge = fmt.Errorf("msg is larger than %d", dns.MaxMsgSize)
)

const (
	fastHTTPTimout = time.Second * 3
)

type DoHClient struct {
	useFastHTTP bool
	preparedURL []byte

	fasthttpClient *fasthttp.HostClient
	netHTTPClient  *http.Client
}

// NewClient returns a doh client
func NewClient(urlStr, addr string, tlsConfig *tls.Config, maxSize int, fastHTTP bool) (*DoHClient, error) {
	// for ease to use, overwrite maxSize.
	switch {
	case maxSize > dns.MaxMsgSize:
		maxSize = dns.MaxMsgSize
	case maxSize < dns.MinMsgSize:
		maxSize = dns.MinMsgSize
	}

	// check urlStr
	u, err := url.ParseRequestURI(urlStr)
	if err != nil {
		return nil, fmt.Errorf("url.ParseRequestURI: %w", err)
	}

	if u.Scheme != "https" {
		return nil, fmt.Errorf("invalid url scheme [%s]", u.Scheme)
	}

	u.ForceQuery = true // make sure we have a '?' at somewhere
	urlStr = u.String()
	if strings.HasSuffix(urlStr, "?") {
		urlStr = urlStr + "dns=" // the only one and the first arg
	} else {
		urlStr = urlStr + "&dns=" // the last arg
	}

	c := new(DoHClient)
	c.preparedURL = []byte(urlStr)
	c.useFastHTTP = fastHTTP

	if fastHTTP {
		c.fasthttpClient = &fasthttp.HostClient{
			Addr: u.Hostname(),
			Dial: func(_ string) (net.Conn, error) {
				d := net.Dialer{Timeout: fastHTTPTimout}
				return d.Dial("tcp", addr)
			},
			IsTLS:                         true,
			TLSConfig:                     tlsConfig,
			ReadTimeout:                   fastHTTPTimout,
			WriteTimeout:                  fastHTTPTimout,
			MaxResponseBodySize:           maxSize,
			DisableHeaderNamesNormalizing: true,
			DisablePathNormalizing:        true,
			NoDefaultUserAgentHeader:      true,
		}
	} else {
		tc := new(tls.Config)
		if tlsConfig != nil {
			tc = tlsConfig.Clone()
		}
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, network, addr)
			},
			TLSClientConfig: tc,

			IdleConnTimeout:       time.Minute,
			ResponseHeaderTimeout: time.Second * 5,
			ForceAttemptHTTP2:     true,
		}

		err := http2.ConfigureTransport(transport) // enable http2
		if err != nil {
			return nil, err
		}
		c.netHTTPClient = &http.Client{
			Transport: transport,
		}
	}

	return c, nil
}

// some consistent string vars
var (
	headerCanonicalKeyAccept = []byte("Accept")
	headerValueMediaType     = []byte("application/dns-message")

	dohCommomHeader = http.Header{"Accept": []string{"application/dns-message"}}
)

func (c *DoHClient) Exchange(ctx context.Context, qRaw []byte, requestLogger *logrus.Entry) (rRaw []byte, rtt time.Duration, err error) {
	t := time.Now()
	r, err := c.exchange(ctx, qRaw, requestLogger)
	return r, time.Since(t), err
}

func (c *DoHClient) exchange(ctx context.Context, qRaw []byte, requestLogger *logrus.Entry) (rRaw []byte, err error) {
	if len(qRaw) < 12 {
		return nil, dns.ErrShortRead // avoid panic when access msg id in m[0] and m[1]
	}

	qRawCopy := bufpool.AcquireMsgBuf(len(qRaw))
	defer bufpool.ReleaseMsgBuf(qRawCopy)
	copy(qRawCopy, qRaw)

	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such
	// as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS
	// request.
	// https://tools.ietf.org/html/rfc8484 4.1
	oldID := utils.ExchangeMsgID(0, qRawCopy)

	// Padding characters for base64url MUST NOT be included.
	// See: https://tools.ietf.org/html/rfc8484 6
	// That's why we use base64.RawURLEncoding
	urlLen := len(c.preparedURL) + base64.RawURLEncoding.EncodedLen(len(qRawCopy))
	urlBytes := bufpool.AcquireMsgBuf(urlLen)
	copy(urlBytes, c.preparedURL)
	base64MsgStart := len(c.preparedURL)
	base64.RawURLEncoding.Encode(urlBytes[base64MsgStart:], qRawCopy)

	if c.useFastHTTP {
		rRaw, err = c.doFasthttp(urlBytes, requestLogger)
		if err != nil {
			return nil, fmt.Errorf("doFasthttp: %w", err)
		}
	} else {
		rRaw, err = c.doHTTP(ctx, string(urlBytes), requestLogger)
		if err != nil {
			return nil, fmt.Errorf("doHTTP: %w", err)
		}
	}

	// change the id back
	if utils.GetMsgID(rRaw) != 0 { // check msg id
		bufpool.ReleaseMsgBuf(rRaw)
		return nil, dns.ErrId
	}
	utils.SetMsgID(oldID, rRaw)
	return rRaw, nil
}

func (c *DoHClient) doFasthttp(url []byte, requestLogger *logrus.Entry) ([]byte, error) {
	//Note: It is forbidden copying Request instances. Create new instances and use CopyTo instead.
	//Request instance MUST NOT be used from concurrently running goroutines.
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	req.SetRequestURIBytes(url)
	req.Header.SetMethod(fasthttp.MethodGet)
	req.Header.SetCanonical(headerCanonicalKeyAccept, headerValueMediaType)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := c.fasthttpClient.Do(req, resp); err != nil {
		return nil, fmt.Errorf("Do: %w", err)
	}

	// check Content_Length
	if resp.Header.ContentLength() > dns.MaxMsgSize {
		return nil, ErrMsgTooLarge
	}

	// check statu code
	statusCode := resp.StatusCode()
	if statusCode != fasthttp.StatusOK {
		return nil, fmt.Errorf("HTTP status codes [%d]", statusCode)
	}

	body := resp.Body()
	if len(body) < 12 {
		return nil, dns.ErrShortRead
	}

	rRaw := bufpool.AcquireMsgBufAndCopy(body)
	return rRaw, nil
}

func (c *DoHClient) doHTTP(ctx context.Context, url string, requestLogger *logrus.Entry) ([]byte, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("NewRequestWithContext: %w", err)
	}
	req.Header = dohCommomHeader.Clone()

	resp, err := c.netHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Do: %w", err)
	}
	defer resp.Body.Close()

	// check Content-Length
	if resp.ContentLength > dns.MaxMsgSize {
		return nil, ErrMsgTooLarge
	}

	// check statu code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status codes [%d]", resp.StatusCode)
	}

	buf := bufpool.AcquireBytesBuf()
	defer bufpool.ReleaseBytesBuf(buf)
	_, err = buf.ReadFrom(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, fmt.Errorf("ReadFrom resp.Body: %w", err)
	}
	body := buf.Bytes()

	if len(body) < 12 {
		return nil, dns.ErrShortRead
	}

	rRaw := bufpool.AcquireMsgBufAndCopy(body)
	return rRaw, nil
}
