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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/IrineSistiana/mos-chinadns/utils"

	"github.com/IrineSistiana/mos-chinadns/bufpool"

	"golang.org/x/sync/singleflight"

	"github.com/sirupsen/logrus"

	"github.com/miekg/dns"

	"github.com/valyala/fasthttp"
)

type DoHClient struct {
	preparedURL []byte
	timeout     time.Duration

	// why using pointer: uint64 atomic value inside HostClient.
	// avoids 32-bit system encountering "invalid memory address" panic
	fasthttpClient *fasthttp.HostClient

	group singleflight.Group
}

// NewClient returns a doh client
func NewClient(url, addr string, tlsConfig *tls.Config, maxSize int, timeout time.Duration) *DoHClient {
	// for ease to use, overwrite maxSize.
	switch {
	case maxSize > dns.MaxMsgSize:
		maxSize = dns.MaxMsgSize
	case maxSize < dns.MinMsgSize:
		maxSize = dns.MinMsgSize
	}

	u := fasthttp.URI{}
	u.Update(url)
	host := string(u.Host())
	if len(host) == 0 {
		host = addr
	}

	c := &DoHClient{
		preparedURL: []byte(url + "?dns="),
		timeout:     timeout,
		fasthttpClient: &fasthttp.HostClient{
			Addr: host,
			Dial: func(_ string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.Dial("tcp", addr)
			},
			IsTLS:                         true,
			TLSConfig:                     tlsConfig,
			ReadTimeout:                   timeout,
			WriteTimeout:                  timeout,
			MaxResponseBodySize:           maxSize,
			DisableHeaderNamesNormalizing: true,
			DisablePathNormalizing:        true,
			NoDefaultUserAgentHeader:      true,
		},
	}
	return c
}

// some consistent string vars
var (
	headerCanonicalKeyAccept = []byte("Accept")
	headerValueMediaType     = []byte("application/dns-message")
)

var bytesBufPool = sync.Pool{
	New: func() interface{} {
		return &bytes.Buffer{}
	},
}

func (c *DoHClient) Exchange(ctx context.Context, qRaw []byte, requestLogger *logrus.Entry) (rRaw []byte, rtt time.Duration, err error) {
	t := time.Now()
	r, err := c.exchange(qRaw, requestLogger)
	return r, time.Since(t), err
}

func (c *DoHClient) exchange(qRaw []byte, requestLogger *logrus.Entry) (rRaw []byte, err error) {
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

	rRaw, err = c.doFasthttp(urlBytes, requestLogger)
	if err != nil {
		return nil, fmt.Errorf("group.Do doFasthttp: %w", err)
	}

	// change the id back
	_ = utils.ExchangeMsgID(oldID, rRaw)
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

	statusCode := resp.StatusCode()
	if statusCode != fasthttp.StatusOK {
		if requestLogger.Logger.IsLevelEnabled(logrus.DebugLevel) {
			requestLogger.Debugf("doFasthttp: HTTP status codes [%d] body [%s]", statusCode, resp.Body())
		}
		return nil, fmt.Errorf("HTTP status codes [%d]", statusCode)
	}

	if resp.IsBodyStream() {
		return nil, fmt.Errorf("resp body is stream")
	}

	body := resp.Body()
	if len(body) < 12 {
		return nil, dns.ErrShortRead
	}

	rRaw := bufpool.AcquireMsgBuf(len(body))
	copy(rRaw, body)
	return rRaw, nil
}
