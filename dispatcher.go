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
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mos-chinadns/bufpool"
	"github.com/IrineSistiana/mos-chinadns/domainlist"

	"github.com/miekg/dns"

	netlist "github.com/IrineSistiana/net-list"
	"github.com/sirupsen/logrus"
)

var (
	errAllServersFailed  = errors.New("all servers are failed")
	errAllServersTimeout = errors.New("all server timeout")
)

type dispatcher struct {
	bindAddr                 string
	localDenyUnusualType     bool
	localDenyResultWithoutIP bool
	localCheckCNAME          bool
	remoteServerDelayStart   time.Duration

	localClient  upstream
	remoteClient upstream

	localIPPolicies     *ipPolicies
	localDomainPolicies *domainPolicies

	localECS  *dns.EDNS0_SUBNET
	remoteECS *dns.EDNS0_SUBNET

	entry *logrus.Entry
}

const (
	queryTimeout = time.Second * 3
)

var (
	timerPool = sync.Pool{}
)

func getTimer(t time.Duration) *time.Timer {
	timer, ok := timerPool.Get().(*time.Timer)
	if !ok {
		return time.NewTimer(t)
	}
	if timer.Reset(t) {
		panic("dispatcher.go getTimer: active timer trapped in timerPool")
	}
	return timer
}

func releaseTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timerPool.Put(timer)
}

func initDispatcher(conf *Config, entry *logrus.Entry) (*dispatcher, error) {
	d := new(dispatcher)
	d.entry = entry

	if len(conf.BindAddr) == 0 {
		return nil, errors.New("missing args: bind address")
	}
	d.bindAddr = conf.BindAddr

	var rootCAs *x509.CertPool
	var err error
	if len(conf.TLSPEMCA) != 0 {
		rootCAs, err = caPath2Pool(conf.TLSPEMCA)
		if err != nil {
			return nil, fmt.Errorf("caPath2Pool: %w", err)
		}
		d.entry.Info("initDispatcher: CA cert loaded")
	}

	if len(conf.LocalServerAddr) == 0 && len(conf.RemoteServerAddr) == 0 {
		return nil, errors.New("missing args: both local server and remote server are empty")
	}

	if len(conf.LocalServerAddr) != 0 {
		client, err := newUpstream(conf.LocalServerAddr, conf.LocalServerProtocol, conf.LocalServerURL, rootCAs)
		if err != nil {
			return nil, fmt.Errorf("init local server: %w", err)
		}
		d.localClient = client
		d.localDenyUnusualType = conf.LocalDenyUnusualType
	}

	if len(conf.RemoteServerAddr) != 0 {
		client, err := newUpstream(conf.RemoteServerAddr, conf.RemoteServerProtocol, conf.RemoteServerURL, rootCAs)
		if err != nil {
			return nil, fmt.Errorf("init remote server: %w", err)
		}
		d.remoteClient = client
		d.remoteServerDelayStart = time.Millisecond * time.Duration(conf.RemoteServerDelayStart)
	}

	d.localDenyUnusualType = conf.LocalDenyUnusualType
	d.localDenyResultWithoutIP = conf.LocalDenyResultsWithoutIP
	d.localCheckCNAME = conf.LocalCheckCNAME

	if len(conf.LocalIPPolicies) != 0 {
		args, err := convPoliciesStr(conf.LocalIPPolicies, convIPPolicyActionStr)
		if err != nil {
			return nil, fmt.Errorf("invalid ip policies string, %w", err)
		}
		p, err := newIPPolicies(args, d.entry)
		if err != nil {
			return nil, fmt.Errorf("loading ip policies, %w", err)
		}
		d.localIPPolicies = p
	}

	if len(conf.LocalDomainPolicies) != 0 {
		args, err := convPoliciesStr(conf.LocalDomainPolicies, convDomainPolicyActionStr)
		if err != nil {
			return nil, fmt.Errorf("invalid domain policies string, %w", err)
		}
		p, err := newDomainPolicies(args, d.entry)
		if err != nil {
			return nil, fmt.Errorf("loading domain policies, %w", err)
		}
		d.localDomainPolicies = p
	}

	if len(conf.LocalECS) != 0 {
		ecs, err := newEDNSSubnet(conf.LocalECS)
		if err != nil {
			return nil, fmt.Errorf("parsing local ECS subnet, %w", err)
		}
		d.localECS = ecs
		d.entry.Info("initDispatcher: local server ECS enabled")
	}

	if len(conf.RemoteECS) != 0 {
		ecs, err := newEDNSSubnet(conf.RemoteECS)
		if err != nil {
			return nil, fmt.Errorf("parsing remote ECS subnet, %w", err)
		}
		d.remoteECS = ecs
		d.entry.Info("initDispatcher: remote server ECS enabled")
	}

	return d, nil
}

func newEDNSSubnet(strECSSubnet string) (*dns.EDNS0_SUBNET, error) {
	strs := strings.SplitN(strECSSubnet, "/", 2)
	if len(strs) != 2 {
		return nil, fmt.Errorf("invalid ECS address [%s], not a CIDR notation", strECSSubnet)
	}

	ip := net.ParseIP(strs[0])
	if ip == nil {
		return nil, fmt.Errorf("invalid ECS address [%s], invalid ip", strECSSubnet)
	}
	sourceNetmask, err := strconv.Atoi(strs[1])
	if err != nil || sourceNetmask > 128 || sourceNetmask < 0 {
		return nil, fmt.Errorf("invalid ECS address [%s], invalid net mask", strECSSubnet)
	}

	ednsSubnet := new(dns.EDNS0_SUBNET)
	// edns family: https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
	// ipv4 = 1
	// ipv6 = 2
	if ip4 := ip.To4(); ip4 != nil {
		ednsSubnet.Family = 1
		ednsSubnet.SourceNetmask = uint8(sourceNetmask)
		ip = ip4
	} else {
		if ip6 := ip.To16(); ip6 != nil {
			ednsSubnet.Family = 2
			ednsSubnet.SourceNetmask = uint8(sourceNetmask)
			ip = ip6
		} else {
			return nil, fmt.Errorf("invalid ECS address [%s], it's not an ipv4 or ipv6 address", strECSSubnet)
		}
	}

	ednsSubnet.Code = dns.EDNS0SUBNET
	ednsSubnet.Address = ip

	// SCOPE PREFIX-LENGTH, an unsigned octet representing the leftmost
	// number of significant bits of ADDRESS that the response covers.
	// In queries, it MUST be set to 0.
	// https://tools.ietf.org/html/rfc7871
	ednsSubnet.SourceScope = 0
	return ednsSubnet, nil
}

func isUnusualType(q *dns.Msg) bool {
	return q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET || (q.Question[0].Qtype != dns.TypeA && q.Question[0].Qtype != dns.TypeAAAA)
}

func (d *dispatcher) serveDNS(q *dns.Msg, entry *logrus.Entry) (r *dns.Msg) {
	rRaw := d.serveRawDNS(q, nil, entry)
	if cap(rRaw) == 0 {
		return nil
	}

	r = new(dns.Msg)
	err := r.Unpack(rRaw)
	bufpool.ReleaseMsgBuf(rRaw)
	if err != nil {
		entry.Warnf("serveDNS: Unpack: %v", err)
	}
	return r
}

// serveRawDNS: q can't be nil, result might be nil
func (d *dispatcher) serveRawDNS(q *dns.Msg, qRaw []byte, requestLogger *logrus.Entry) []byte {

	// if qRaw is nil, we will pack the q
	// and release it buffer after func returned
	if qRaw == nil {
		buf := bufpool.AcquirePackBuf()
		var err error
		qRaw, err = q.PackBuffer(buf)
		if err != nil {
			requestLogger.Warnf("serveDNS: q.PackBuffer: %v", err)
			bufpool.ReleasePackBuf(buf)
			return nil
		}
		defer bufpool.ReleasePackBuf(qRaw)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var doLocal, doRemote, forceLocal bool
	if d.localClient != nil {
		doLocal = true
		if isUnusualType(q) {
			doLocal = !d.localDenyUnusualType
		} else {
			if d.localDomainPolicies != nil {
				p := d.localDomainPolicies.check(q.Question[0].Name)
				switch p {
				case policyActionForce:
					doLocal = true
					forceLocal = true
				case policyActionAccept:
					doLocal = true
				case policyActionDeny:
					doLocal = false
				}
				requestLogger.Debugf("serveDNS: localDomainPolicies: accept: %v, force %v", doLocal, forceLocal)
			}
		}
	}

	if d.remoteClient != nil {
		doRemote = true
		switch {
		case forceLocal:
			doRemote = false
		}
	}

	resChan := make(chan []byte, 1)

	serverFailedNotify := make(chan struct{}, 0)
	upstreamWG := sync.WaitGroup{}
	var localServerDone chan struct{}
	var localServerFailed chan struct{}

	// local
	if doLocal {
		localServerDone = make(chan struct{})
		localServerFailed = make(chan struct{})
		upstreamWG.Add(1)
		go func() {
			defer upstreamWG.Done()
			requestLogger.Debug("serveDNS: query local server")
			rRaw, rtt, err := d.queryLocal(ctx, q, qRaw, requestLogger)
			if err != nil {
				if ctx.Err() == nil {
					requestLogger.Warnf("serveDNS: local server failed: %v", err)
				}
				close(localServerFailed)
				return
			}

			requestLogger.Debugf("serveDNS: get reply from local, rtt: %dms", rtt.Milliseconds())
			if !forceLocal && !d.acceptLocalRes(rRaw, requestLogger) {
				requestLogger.Debug("serveDNS: local result denied")
				close(localServerFailed)
				bufpool.ReleaseMsgBuf(rRaw)
				return
			}

			select {
			case resChan <- rRaw:
			default:
				bufpool.ReleaseMsgBuf(rRaw)
			}
			requestLogger.Debug("serveDNS: local result accepted")
			close(localServerDone)
		}()
	}

	// remote
	if doRemote {
		upstreamWG.Add(1)
		go func() {
			defer upstreamWG.Done()

			if doLocal && d.remoteServerDelayStart > 0 {
				timer := getTimer(d.remoteServerDelayStart)
				select {
				case <-localServerDone:
					releaseTimer(timer)
					return
				case <-localServerFailed:
				case <-timer.C:
				}
				releaseTimer(timer)
			}

			requestLogger.Debug("serveDNS: query remote server")
			rRaw, rtt, err := d.queryRemote(ctx, q, qRaw, requestLogger)
			if err != nil {
				if ctx.Err() == nil {
					requestLogger.Warnf("serveDNS: remote server failed: %v", err)
				}
				return
			}
			requestLogger.Debugf("serveDNS: get reply from remote, rtt: %dms", rtt.Milliseconds())

			select {
			case resChan <- rRaw:
			default:
				bufpool.ReleaseMsgBuf(rRaw)
			}
		}()
	}

	// watcher
	serveDNSWG := sync.WaitGroup{}
	serveDNSWG.Add(1)
	defer serveDNSWG.Done()
	go func() {
		upstreamWG.Wait()
		// there has a very small probability that
		// below select{} will select case:<-serverFailedNotify
		// if both case1 and case2 are in ready state.
		// dont close serverFailedNotify if resChan is ready
		if len(resChan) == 0 {
			close(serverFailedNotify)
		}

		serveDNSWG.Wait()
		emptyResChan(resChan) // some buf might still be traped in resChan
	}()

	timeoutTimer := getTimer(queryTimeout)
	defer releaseTimer(timeoutTimer)

	select {
	case rRaw := <-resChan:
		return rRaw
	case <-serverFailedNotify:
		requestLogger.Warn("serveDNS: query failed: all servers failed")
		r := new(dns.Msg)
		r.SetReply(q)
		r.Rcode = dns.RcodeServerFailure
		buf := bufpool.AcquirePackBuf()
		rRawWithPackBuf, err := r.PackBuffer(buf)
		if err != nil {
			requestLogger.Warnf("serveDNS: r.PackBuffer: %v", err)
			bufpool.ReleasePackBuf(buf)
			return nil
		}
		rRaw := bufpool.AcquireMsgBufAndCopy(rRawWithPackBuf)
		bufpool.ReleasePackBuf(rRawWithPackBuf)
		return rRaw
	case <-timeoutTimer.C:
		requestLogger.Warn("serveDNS: query failed: timeout")
		return nil
	}
}

func emptyResChan(c <-chan []byte) {
	for {
		select {
		case rRaw := <-c:
			if cap(rRaw) != 0 {
				bufpool.ReleaseMsgBuf(rRaw)
			}
		default:
			return
		}
	}
}

func (d *dispatcher) queryUpstream(ctx context.Context, q *dns.Msg, qRaw []byte, u upstream, ecs *dns.EDNS0_SUBNET, requestLogger *logrus.Entry) (rRaw []byte, rtt time.Duration, err error) {
	if ecs != nil {
		q, appended := appendECSIfNotExist(q, d.localECS)
		if appended {
			buf := bufpool.AcquirePackBuf()
			qRawCopy, err := q.PackBuffer(buf)
			if err != nil {
				bufpool.ReleasePackBuf(qRawCopy)
				return nil, 0, err
			}
			defer bufpool.ReleasePackBuf(qRawCopy)
			return u.Exchange(ctx, qRawCopy, requestLogger)
		}
	}
	return u.Exchange(ctx, qRaw, requestLogger)
}

func (d *dispatcher) queryLocal(ctx context.Context, q *dns.Msg, qRaw []byte, requestLogger *logrus.Entry) (rRaw []byte, rtt time.Duration, err error) {
	return d.queryUpstream(ctx, q, qRaw, d.localClient, d.localECS, requestLogger)
}

func (d *dispatcher) queryRemote(ctx context.Context, q *dns.Msg, qRaw []byte, requestLogger *logrus.Entry) (rRaw []byte, rtt time.Duration, err error) {
	return d.queryUpstream(ctx, q, qRaw, d.remoteClient, d.remoteECS, requestLogger)
}

// both q and ecs shouldn't be nil, the returned m is a deep-copy if ecs is appended.
func appendECSIfNotExist(q *dns.Msg, ecs *dns.EDNS0_SUBNET) (m *dns.Msg, appended bool) {
	opt := q.IsEdns0()
	if opt == nil { // we need a new opt
		o := new(dns.OPT)
		o.SetUDPSize(4096) // TODO: is this big enough?
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.Option = []dns.EDNS0{ecs}
		qCopy := q.Copy()
		qCopy.Extra = append(qCopy.Extra, o)
		return qCopy, true
	}

	hasECS := false // check if msg q already has a ECS section
	for o := range opt.Option {
		if opt.Option[o].Option() == dns.EDNS0SUBNET {
			hasECS = true
			break
		}
	}

	if !hasECS {
		qCopy := q.Copy()
		opt := qCopy.IsEdns0()
		opt.Option = append(opt.Option, ecs)
		return qCopy, true
	}

	return q, false
}

// check if local result is ok to accept, res can be nil.
func (d *dispatcher) acceptLocalRes(rRaw []byte, requestLogger *logrus.Entry) (ok bool) {

	res := new(dns.Msg)
	err := res.Unpack(rRaw)
	if err != nil {
		requestLogger.Debugf("acceptLocalRes: false, Unpack: %v", err)
		return false
	}

	if res == nil {
		requestLogger.Debug("acceptLocalRes: false: result is nil")
		return false
	}

	if res.Rcode != dns.RcodeSuccess {
		requestLogger.Debugf("acceptLocalRes: false: Rcode=%s", dns.RcodeToString[res.Rcode])
		return false
	}

	if isUnusualType(res) {
		if d.localDenyUnusualType {
			requestLogger.Debug("acceptLocalRes: false: unusual type")
			return false
		}

		requestLogger.Debug("acceptLocalRes: true: unusual type")
		return true
	}

	// check CNAME
	if d.localDomainPolicies != nil && d.localCheckCNAME == true {
		for i := range res.Answer {
			if cname, ok := res.Answer[i].(*dns.CNAME); ok {
				p := d.localDomainPolicies.check(cname.Target)
				switch p {
				case policyActionAccept, policyActionForce:
					requestLogger.Debug("acceptLocalRes: true: matched by CNAME")
					return true
				case policyActionDeny:
					requestLogger.Debug("acceptLocalRes: false: matched by CNAME")
					return false
				default: // policyMissing
					continue
				}
			}
		}
	}

	// check ip
	var hasIP bool
	if d.localIPPolicies != nil {
		for i := range res.Answer {
			var ip netlist.IPv6
			var err error
			switch tmp := res.Answer[i].(type) {
			case *dns.A:
				ip, err = netlist.Conv(tmp.A)
			case *dns.AAAA:
				ip, err = netlist.Conv(tmp.AAAA)
			default:
				continue
			}

			hasIP = true

			if err != nil {
				requestLogger.Warnf("acceptLocalRes: internal err: netlist.Conv %v", err)
				continue
			}

			p := d.localIPPolicies.check(ip)
			switch p {
			case policyActionAccept:
				requestLogger.Debug("acceptLocalRes: true: matched by ip")
				return true
			case policyActionDeny:
				requestLogger.Debug("acceptLocalRes: false: matched by ip")
				return false
			default: // policyMissing
				continue
			}
		}
	}

	if d.localDenyResultWithoutIP && !hasIP {
		requestLogger.Debug("acceptLocalRes: false: no ip RR")
		return false
	}

	requestLogger.Debug("acceptLocalRes: true: default accpet")
	return true
}

func caPath2Pool(ca string) (*x509.CertPool, error) {
	pem, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %w", err)
	}

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(pem); !ok {
		return nil, fmt.Errorf("AppendCertsFromPEM: no certificate was successfully parsed in %s", ca)
	}
	return rootCAs, nil
}

type policyAction uint8

const (
	policyActionForceStr   string = "force"
	policyActionAcceptStr  string = "accept"
	policyActionDenyStr    string = "deny"
	policyActionDenyAllStr string = "deny_all"

	policyActionForce policyAction = iota
	policyActionAccept
	policyActionDeny
	policyActionDenyAll
	policyActionMissing
)

var convIPPolicyActionStr = map[string]policyAction{
	policyActionAcceptStr:  policyActionAccept,
	policyActionDenyStr:    policyActionDeny,
	policyActionDenyAllStr: policyActionDenyAll,
}

var convDomainPolicyActionStr = map[string]policyAction{
	policyActionForceStr:   policyActionForce,
	policyActionAcceptStr:  policyActionAccept,
	policyActionDenyStr:    policyActionDeny,
	policyActionDenyAllStr: policyActionDenyAll,
}

type rawPolicy struct {
	action policyAction
	args   string
}

type ipPolicies struct {
	policies []ipPolicy
}

type ipPolicy struct {
	action policyAction
	list   *netlist.List
}

type domainPolicies struct {
	policies []domainPolicy
}

type domainPolicy struct {
	action policyAction
	list   *domainlist.List
}

func convPoliciesStr(s string, f map[string]policyAction) ([]rawPolicy, error) {
	ps := make([]rawPolicy, 0)

	policiesStr := strings.Split(s, "|")
	for i := range policiesStr {
		pStr := strings.SplitN(policiesStr[i], ":", 2)

		p := rawPolicy{}
		action, ok := f[pStr[0]]
		if !ok {
			return nil, fmt.Errorf("unknown action [%s]", pStr[0])
		}
		p.action = action

		if len(pStr) == 2 {
			p.args = pStr[1]
		}

		ps = append(ps, p)
	}

	return ps, nil
}

func newIPPolicies(psArgs []rawPolicy, entry *logrus.Entry) (*ipPolicies, error) {
	ps := &ipPolicies{
		policies: make([]ipPolicy, 0),
	}

	for i := range psArgs {
		p := ipPolicy{}
		p.action = psArgs[i].action

		file := psArgs[i].args
		if len(file) != 0 {
			list, err := netlist.NewListFromFile(file)
			if err != nil {
				return nil, fmt.Errorf("failed to load ip file from %s, %w", file, err)
			}
			p.list = list
			entry.Infof("newIPPolicies: ip list %s loaded, length %d", file, list.Len())
		}

		ps.policies = append(ps.policies, p)
	}

	return ps, nil
}

// ps can not be nil
func (ps *ipPolicies) check(ip netlist.IPv6) policyAction {
	for p := range ps.policies {
		if ps.policies[p].action == policyActionDenyAll {
			return policyActionDeny
		}

		if ps.policies[p].list != nil && ps.policies[p].list.Contains(ip) {
			return ps.policies[p].action
		}
	}

	return policyActionMissing
}

func newDomainPolicies(psArgs []rawPolicy, entry *logrus.Entry) (*domainPolicies, error) {
	ps := &domainPolicies{
		policies: make([]domainPolicy, 0),
	}

	for i := range psArgs {
		p := domainPolicy{}
		p.action = psArgs[i].action

		file := psArgs[i].args
		if len(file) != 0 {
			list, err := domainlist.LoadFormFile(file)
			if err != nil {
				return nil, fmt.Errorf("failed to load domain file from %s, %w", file, err)
			}
			p.list = list
			entry.Infof("newDomainPolicies: domain list %s loaded, length %d", file, list.Len())
		}

		ps.policies = append(ps.policies, p)
	}

	return ps, nil
}

// check: ps can not be nil
func (ps *domainPolicies) check(fqdn string) policyAction {
	for p := range ps.policies {
		if ps.policies[p].action == policyActionDenyAll {
			return policyActionDeny
		}

		if ps.policies[p].list != nil && ps.policies[p].list.Has(fqdn) {
			return ps.policies[p].action
		}
	}

	return policyActionMissing
}
