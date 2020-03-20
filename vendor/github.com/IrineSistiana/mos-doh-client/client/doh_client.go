// Copyright (c) 2020 IrineSistiana
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package client

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"

	"github.com/miekg/dns"

	"github.com/valyala/fasthttp"
)

type DoHClient struct {
	preparedURL []byte

	httpClient  *fasthttp.Client
	bufPool1024 *sync.Pool
	entry       *logrus.Entry

	timeout time.Duration
}

//NewClient returns a doh client
func NewClient(url, addr string, sv bool, maxSize int, timeout time.Duration, entry *logrus.Entry) *DoHClient {
	// for ease to use, overwrite maxSize.
	switch {
	case maxSize > dns.MaxMsgSize:
		maxSize = dns.MaxMsgSize
	case maxSize < dns.MinMsgSize:
		maxSize = dns.MinMsgSize
	}

	tlsConf := &tls.Config{InsecureSkipVerify: sv}
	c := &DoHClient{
		preparedURL: []byte(url + queryParameter8484),
		bufPool1024: &sync.Pool{
			New: func() interface{} {
				return make([]byte, 1024)
			}},
		httpClient: &fasthttp.Client{
			TLSConfig:           tlsConf,
			MaxResponseBodySize: maxSize,
		},
		entry:   entry,
		timeout: timeout,
	}

	if len(addr) != 0 {
		c.httpClient.Dial = func(_ string) (net.Conn, error) {
			return net.Dial("tcp", addr)
		}
	}
	return c
}

// some consistent string vars
var (
	queryParameter8484   = "?dns="
	headerKeyAccept      = "accept"
	headerValueMediaType = "application/dns-message"
)

func (c *DoHClient) Exchange(q *dns.Msg) (*dns.Msg, error) {
	buf := c.bufPool1024.Get().([]byte)
	defer c.bufPool1024.Put(buf)

	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such
	// as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS
	// request.
	// https://tools.ietf.org/html/rfc8484 4.1

	id := q.Id
	q.Id = 0
	defer func() { q.Id = id }()

	wireMsg, err := q.PackBuffer(buf)
	if err != nil {
		return nil, err
	}

	// we assume that most of urls are short than 1024 characters
	var urlBuf []byte
	urlLength := len(c.preparedURL) + base64.RawURLEncoding.EncodedLen(len(wireMsg))
	if urlLength > 1024 {
		urlBuf = make([]byte, urlLength)
		// this buf is larger than 1024, it's ok to put it back to pool
		defer c.bufPool1024.Put(urlBuf)
	} else {
		urlBuf = c.bufPool1024.Get().([]byte)
		defer c.bufPool1024.Put(urlBuf)
	}
	copy(urlBuf, c.preparedURL)
	base64.RawURLEncoding.Encode(urlBuf[len(c.preparedURL):urlLength], wireMsg)

	//Note: It is forbidden copying Request instances. Create new instances and use CopyTo instead.
	//Request instance MUST NOT be used from concurrently running goroutines.
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	req.SetRequestURIBytes(urlBuf[:urlLength])
	req.Header.Set(headerKeyAccept, headerValueMediaType)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := c.httpClient.DoTimeout(req, resp, c.timeout); err != nil {
		return nil, fmt.Errorf("DoTimeout: %w", err)
	}

	statusCode := resp.StatusCode()
	if statusCode != fasthttp.StatusOK {
		if c.entry.Logger.IsLevelEnabled(logrus.DebugLevel) {
			c.entry.Debugf("Exchange: HTTP status codes [%d] body [%s]", statusCode, resp.Body())
		}
		return nil, fmt.Errorf("HTTP status codes [%d]", statusCode)
	}

	r := new(dns.Msg)
	err = r.Unpack(resp.Body())
	if err != nil {
		return nil, fmt.Errorf("Unpack: %w", err)
	}
	return r, nil
}

//ServeDNS impliment the interface
func (c *DoHClient) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {

	r, err := c.Exchange(q)
	if err != nil {
		c.entry.Warnf("ServeDNS: Exchange: %v", err)
	}

	if r != nil {
		w.WriteMsg(r)
	}

	//We do not need to call Close() here
	//defer w.Close()
}
