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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/IrineSistiana/mos-chinadns/utils"

	"github.com/IrineSistiana/mos-chinadns/bufpool"
	"github.com/IrineSistiana/mos-chinadns/dohclient"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	tlsHandshakeTimeout = time.Second * 3
)

type upstream interface {
	Exchange(ctx context.Context, qRaw []byte, requestLogger *logrus.Entry) (rRaw []byte, rtt time.Duration, err error)
}

type upstreamTCP struct {
	addr string
}

type upstreamUDP struct {
	addr       string
	maxUDPSize int
	cp         *connPool
}

type upstreamTLS struct {
	addr      string
	tlsConfig *tls.Config
	cp        *connPool
}

func newUpstream(sc *BasicServerConfig, rootCAs *x509.CertPool) (upstream, error) {
	if sc == nil {
		panic("newUpstream: sc is nil")
	}

	var client upstream
	var err error
	switch sc.Protocol {
	case "tcp":
		client = &upstreamTCP{
			addr: sc.Addr,
		}
	case "udp", "":
		client = &upstreamUDP{
			addr:       sc.Addr,
			maxUDPSize: 1480,
			cp:         newConnPool(0xffff, time.Second*10, time.Second*5),
		}
	case "dot":
		tlsConf := &tls.Config{
			ServerName:         sc.DoT.ServerName,
			RootCAs:            rootCAs,
			ClientSessionCache: tls.NewLRUClientSessionCache(64),
		}

		timeout := time.Duration(sc.DoT.IdleTimeout) * time.Second
		client = &upstreamTLS{
			addr:      sc.Addr,
			tlsConfig: tlsConf,
			cp:        newConnPool(0xffff, timeout, timeout>>1),
		}
	case "doh":
		tlsConf := &tls.Config{
			// don't have to set servername here, fasthttp will do it itself.
			RootCAs:            rootCAs,
			ClientSessionCache: tls.NewLRUClientSessionCache(64),
		}

		if len(sc.DoH.URL) == 0 {
			return nil, fmt.Errorf("protocol [%s] needs URL", sc.Protocol)
		}
		client, err = dohclient.NewClient(sc.DoH.URL, sc.Addr, tlsConf, dns.MaxMsgSize, sc.DoH.FastHTTP)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupport protocol: %s", sc.Protocol)
	}

	return client, nil
}

func (u *upstreamTCP) Exchange(ctx context.Context, qRaw []byte, _ *logrus.Entry) (rRaw []byte, rtt time.Duration, err error) {
	t := time.Now()
	r, err := u.exchange(ctx, qRaw)
	return r, time.Since(t), err
}

func (u *upstreamTCP) exchange(ctx context.Context, qRaw []byte) (rRaw []byte, err error) {
	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	d := net.Dialer{}
	c, err := d.DialContext(ctx, "tcp", u.addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	go func() {
		select {
		case <-queryCtx.Done():
			c.SetDeadline(time.Now())
		}
	}()

	err = writeMsgToTCP(c, qRaw)
	if err != nil {
		return nil, err
	}
	rRaw, err = readMsgFromTCP(c)
	if err != nil {
		return nil, err
	}

	msgID := utils.GetMsgID(qRaw)
	if utils.GetMsgID(rRaw) != msgID {
		bufpool.ReleaseMsgBuf(rRaw)
		return nil, dns.ErrId
	}
	return rRaw, nil
}

func (u *upstreamUDP) Exchange(ctx context.Context, qRaw []byte, _ *logrus.Entry) (rRaw []byte, rtt time.Duration, err error) {
	t := time.Now()
	rRaw, err = u.exchange(ctx, qRaw)
	return rRaw, time.Since(t), err
}

func (u *upstreamUDP) exchange(ctx context.Context, qRaw []byte) (rRaw []byte, err error) {
	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var isNewConn bool
	c := u.cp.get()
	if c == nil {
		d := net.Dialer{}
		c, err = d.DialContext(ctx, "udp", u.addr)
		if err != nil {
			return nil, err
		}
		isNewConn = true
	}
	c.SetDeadline(time.Time{})

	// this once is to make sure that the following
	// c.SetDeadline wouldn't be called after exchange() is returned
	once := sync.Once{}
	defer once.Do(func() {}) // do nothing, just fire the once
	go func() {
		select {
		case <-queryCtx.Done():
			once.Do(func() { c.SetDeadline(time.Now()) })
		}
	}()

	_, err = c.Write(qRaw)
	if err != nil {
		c.Close()
		return nil, err
	}

	buf := bufpool.AcquireMsgBuf(u.maxUDPSize)
	defer bufpool.ReleaseMsgBuf(buf)
read:
	n, err := c.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() && ctx.Err() != nil {
			// err caused by cancelled ctx, it's ok to reuse the connection
			u.cp.put(c)
			return nil, err
		}
		c.Close()
		return nil, err
	}

	if n < 12 {
		c.Close()
		return nil, dns.ErrShortRead
	}
	data := buf[:n]
	if utils.GetMsgID(data) != utils.GetMsgID(qRaw) {
		if !isNewConn {
			// this connection is reused, data might be the reply
			// of last qRaw, not this qRaw.
			// try to read again
			goto read
		} else {
			// new connection should never receive a mismatched id, this is an error
			c.Close()
			return nil, dns.ErrId
		}
	}

	u.cp.put(c)
	rRaw = bufpool.AcquireMsgBufAndCopy(data)
	return rRaw, nil
}

func (u *upstreamTLS) Exchange(ctx context.Context, qRaw []byte, entry *logrus.Entry) (rRaw []byte, rtt time.Duration, err error) {
	t := time.Now()
	rRaw, err = u.exchange(ctx, qRaw, entry, false)
	return rRaw, time.Since(t), err
}

func (u *upstreamTLS) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{}
	c, err := d.DialContext(ctx, "tcp", u.addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(c, u.tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
	// try handshake first
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	return tlsConn, nil
}

func (u *upstreamTLS) exchange(ctx context.Context, qRaw []byte, entry *logrus.Entry, forceNewConn bool) (rRaw []byte, err error) {
	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var isNewConn bool
	var c net.Conn
	if !forceNewConn { // we want a new connection
		c = u.cp.get()
	}

	// if we need a new conn
	if c == nil {
		tlsConn, err := u.dial(ctx)
		if err != nil {
			return nil, err
		}
		c = tlsConn
		isNewConn = true
	}
	c.SetDeadline(time.Time{})

	// this once is to make sure that the following
	// c.SetDeadline wouldn't be called after exchange() is returned
	once := sync.Once{}
	defer once.Do(func() {}) // do nothing, just fire the once
	go func() {
		select {
		case <-queryCtx.Done():
			once.Do(func() { c.SetDeadline(time.Now()) })
		}
	}()

	// we might spend too much time on tlsConn.Handshake()
	// deadline might have been passed, write might get a err, but the conn is healty.
	err = writeMsgToTCP(c, qRaw)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() && ctx.Err() != nil {
			// err caused by cancelled ctx, it's ok to reuse the connection
			u.cp.put(c)
			return nil, err
		}

		if isNewConn { // we don't try another write for new connection
			c.Close()
			return nil, err
		}

		c.Close()
		// reused connection got an unexpected err, open a new conn and try write again
		return u.exchange(ctx, qRaw, entry, true)
	}

read:
	rRaw, err = readMsgFromTCP(c)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() && ctx.Err() != nil {
			// err caused by cancelled ctx, it's ok to reuse the connection
			u.cp.put(c)
			return nil, err
		}

		if isNewConn {
			c.Close()
			return nil, err
		}
		c.Close()
		return u.exchange(ctx, qRaw, entry, true) // reused connection, let's try a new connection
	}

	if utils.GetMsgID(rRaw) != utils.GetMsgID(qRaw) {
		bufpool.ReleaseMsgBuf(rRaw)
		if !isNewConn {
			// this connection is reused, data might be the reply
			// of last qRaw, not this qRaw.
			// try to read again
			goto read
		} else {
			// new connection should not receive a mismatched id, this is an error
			c.Close()
			return nil, dns.ErrId
		}
	}

	u.cp.put(c)
	return rRaw, nil
}

type connPool struct {
	sync.Mutex
	maxSize          int
	ttl              time.Duration
	cleannerInterval time.Duration

	pool      []poolElem
	lastClean time.Time
}

type poolElem struct {
	net.Conn
	lastUsed time.Time
}

func newConnPool(size int, ttl, gcInterval time.Duration) *connPool {
	return &connPool{
		maxSize:          size,
		ttl:              ttl,
		cleannerInterval: gcInterval,
		pool:             make([]poolElem, 0, 64),
	}

}

// runCleanner must run under lock
func (p *connPool) runCleanner(force bool) {
	if p == nil && len(p.pool) == 0 {
		return
	}

	//scheduled for forced
	if force || time.Since(p.lastClean) > p.cleannerInterval {
		p.lastClean = time.Now()
		res := p.pool[:0]
		for i := range p.pool {

			// remove expired conns
			if time.Since(p.pool[i].lastUsed) < p.ttl {
				res = append(res, p.pool[i])
			} else { // expired, release the resources
				p.pool[i].Conn.Close()
				p.pool[i].Conn = nil
			}
		}
		p.pool = res
	}

	//when the pool is full
	if len(p.pool) >= p.maxSize {
		res := p.pool[:0]
		mid := len(p.pool) >> 1
		for i := range p.pool {
			// forcely remove half conns first
			if i < mid {
				p.pool[i].Conn.Close()
				p.pool[i].Conn = nil
			}

			//then remove expired conns
			if time.Since(p.pool[i].lastUsed) < p.ttl {
				res = append(res, p.pool[i])
			} else {
				p.pool[i].Conn.Close()
				p.pool[i].Conn = nil
			}
		}
		p.pool = res
	}
}

func (p *connPool) put(c net.Conn) {
	if c == nil {
		return
	}

	if p == nil || p.maxSize <= 0 || p.ttl <= 0 {
		c.Close()
		return
	}

	p.Lock()
	defer p.Unlock()

	p.runCleanner(false)

	if len(p.pool) >= p.maxSize {
		c.Close() // pool is full, drop it
	} else {
		p.pool = append(p.pool, poolElem{Conn: c, lastUsed: time.Now()})
	}
}

func (p *connPool) get() (c net.Conn) {
	if p == nil {
		return nil
	}
	if p.maxSize <= 0 || p.ttl <= 0 {
		return nil
	}

	p.Lock()
	defer p.Unlock()

	p.runCleanner(false)

	if len(p.pool) > 0 {
		e := p.pool[len(p.pool)-1]
		p.pool[len(p.pool)-1].Conn = nil
		p.pool = p.pool[:len(p.pool)-1]

		if time.Since(e.lastUsed) > p.ttl {
			e.Conn.Close() // expired
			// the last elem is expired, means all elems are expired
			// remove them asap
			p.runCleanner(true)
			return nil
		}
		return e.Conn
	}
	return nil
}
