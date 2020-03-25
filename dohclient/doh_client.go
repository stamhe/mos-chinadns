//     Copyright (C) 2020, IrineSistiana
//
//     This file is part of mos-chinadns.
//
//     mosdns is free software: you can redistribute it and/or modify
//     it under the terms of the GNU General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     mosdns is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU General Public License for more details.
//
//     You should have received a copy of the GNU General Public License
//     along with this program.  If not, see <https://www.gnu.org/licenses/>.

package dohclient

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/Sirupsen/logrus"

	"github.com/miekg/dns"

	"github.com/valyala/fasthttp"
)

type DoHClient struct {
	preparedURL []byte

	fasthttpClient fasthttp.HostClient

	group   singleflight.Group
	timeout time.Duration
}

// NewClient returns a doh client
func NewClient(url, addr string, sv bool, maxSize int, timeout time.Duration) *DoHClient {
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

	tlsConf := &tls.Config{
		InsecureSkipVerify: sv,
	}
	c := &DoHClient{
		preparedURL: []byte(url + queryParameter8484),
		fasthttpClient: fasthttp.HostClient{
			Addr: host,
			Dial: func(_ string) (net.Conn, error) {
				return net.Dial("tcp", addr)
			},
			IsTLS:                         true,
			TLSConfig:                     tlsConf,
			ReadTimeout:                   timeout,
			WriteTimeout:                  timeout,
			MaxResponseBodySize:           maxSize,
			DisableHeaderNamesNormalizing: true,
		},
		timeout: timeout,
	}
	return c
}

// some consistent string vars
var (
	queryParameter8484       = "?dns="
	headerCanonicalKeyAccept = []byte("Accept")
	headerValueMediaType     = []byte("application/dns-message")
	strGet                   = []byte("GET")
)

// buf pool with len(b) >= 512
var bufPool512 = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 512)
	}}

var bytesBufPool = sync.Pool{
	New: func() interface{} {
		return &bytes.Buffer{}
	},
}

func (c *DoHClient) Exchange(q *dns.Msg, requestLogger *logrus.Entry) (*dns.Msg, error) {

	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such
	// as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS
	// request.
	// https://tools.ietf.org/html/rfc8484 4.1

	qCopy := *q // just shadow copy, we only need to change q.Id
	qCopy.Id = 0

	buf := bufPool512.Get().([]byte)
	defer bufPool512.Put(buf)
	wireMsg, err := qCopy.PackBuffer(buf)
	if err != nil {
		return nil, err
	}
	if len(wireMsg) > len(buf) {
		// this buf is larger than 512, it's ok to put it back to pool
		defer bufPool512.Put(wireMsg[:cap(wireMsg)])
	}

	base64buf := make([]byte, base64.RawURLEncoding.EncodedLen(len(wireMsg)))
	base64.RawURLEncoding.Encode(base64buf, wireMsg)
	payload := string(base64buf)

	vr, err, shared := c.group.Do(payload, func() (interface{}, error) { return c.doWithPayload(base64buf, requestLogger) })
	if shared {
		requestLogger.Debug("Exchange: shared payload")
	}
	c.group.Forget(payload)
	if err != nil {
		return nil, err
	}
	r, ok := vr.(*dns.Msg)
	if ok {
		// change r.Id back
		r.Id = q.Id
		return r, nil
	}
	return nil, nil
}

func (c *DoHClient) doWithPayload(payload []byte, requestLogger *logrus.Entry) (*dns.Msg, error) {
	urlBuf := bytesBufPool.Get().(*bytes.Buffer)
	defer bytesBufPool.Put(urlBuf)
	urlBuf.Reset()
	urlBuf.Grow(len(c.preparedURL) + len(payload))
	urlBuf.Write(c.preparedURL)
	urlBuf.Write(payload)

	r, err := c.doFasthttp(urlBuf.Bytes(), requestLogger)
	if err != nil {
		return nil, fmt.Errorf("doFasthttp: %w", err)
	}

	return r, nil
}

func (c *DoHClient) doFasthttp(url []byte, requestLogger *logrus.Entry) (*dns.Msg, error) {
	//Note: It is forbidden copying Request instances. Create new instances and use CopyTo instead.
	//Request instance MUST NOT be used from concurrently running goroutines.
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	req.SetRequestURIBytes(url)
	req.Header.SetMethodBytes(strGet)
	req.Header.SetCanonical(headerCanonicalKeyAccept, headerValueMediaType)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := c.fasthttpClient.DoTimeout(req, resp, c.timeout); err != nil {
		return nil, fmt.Errorf("DoTimeout: %w", err)
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

	r := new(dns.Msg)
	err := r.Unpack(resp.Body())
	if err != nil {
		return nil, fmt.Errorf("Unpack: %w", err)
	}
	return r, nil
}
