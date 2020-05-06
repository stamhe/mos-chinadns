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
	"crypto/tls"
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

	"github.com/IrineSistiana/mos-chinadns/dohclient"

	"github.com/miekg/dns"

	netlist "github.com/IrineSistiana/net-list"
	"github.com/sirupsen/logrus"
)

type upstream interface {
	Exchange(q *dns.Msg, requestLogger *logrus.Entry) (*dns.Msg, time.Duration, error)
}

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

type upstreamTCPUDP struct {
	client dns.Client
	addr   string
}

func (u *upstreamTCPUDP) Exchange(q *dns.Msg, _ *logrus.Entry) (r *dns.Msg, rtt time.Duration, err error) {
	r, rtt, err = u.client.Exchange(q, u.addr)
	return
}

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

	if len(conf.LocalServerAddr) == 0 && len(conf.RemoteServerAddr) == 0 {
		return nil, errors.New("missing args: both local server and remote server are empty")
	}

	if len(conf.LocalServerAddr) != 0 {
		client, err := newClient(conf.LocalServerAddr, conf.LocalServerProtocol, conf.LocalServerURL, conf.LocalServerPEMCA)
		if err != nil {
			return nil, fmt.Errorf("init local server: %w", err)
		}
		d.localClient = client
		d.localDenyUnusualType = conf.LocalDenyUnusualType
	}

	if len(conf.RemoteServerAddr) != 0 {
		client, err := newClient(conf.RemoteServerAddr, conf.RemoteServerProtocol, conf.RemoteServerURL, conf.RemoteServerPEMCA)
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

func (d *dispatcher) ListenAndServe(network string) error {
	server := &dns.Server{Addr: d.bindAddr, Net: network, Handler: d, UDPSize: 1480}
	return server.ListenAndServe()
}

// ServeDNS implement the interface
func (d *dispatcher) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	r := d.serveDNS(q)
	if r != nil {
		buf := bufpool.AcquirePackBuf()
		data, err := r.PackBuffer(buf)
		if err != nil {
			bufpool.ReleasePackBuf(buf)
			d.entry.Warnf("ServeDNS: PackBuffer: %v", err)
			return
		}

		_, err = w.Write(data)
		bufpool.ReleasePackBuf(data)
		if err != nil {
			d.entry.Warnf("ServeDNS: Write: %v", err)
		}
	}
}

func isUnusualType(q *dns.Msg) bool {
	return q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET || (q.Question[0].Qtype != dns.TypeA && q.Question[0].Qtype != dns.TypeAAAA)
}

// serveDNS: q can't be nil, r might be nil
func (d *dispatcher) serveDNS(q *dns.Msg) *dns.Msg {
	requestLogger := d.entry.WithFields(logrus.Fields{
		"id":       q.Id,
		"question": q.Question,
	})

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

	resChan := make(chan *dns.Msg, 1)
	serverFailedNotify := make(chan struct{}, 0)
	wg := sync.WaitGroup{}
	var localServerDone chan struct{}
	var localServerFailed chan struct{}

	// local
	if doLocal {
		localServerDone = make(chan struct{})
		localServerFailed = make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			requestLogger.Debug("serveDNS: query local server")
			res, rtt, err := d.queryLocal(q, requestLogger)
			if err != nil {
				requestLogger.Warnf("serveDNS: local server failed: %v", err)
				close(localServerFailed)
				return
			}

			requestLogger.Debugf("serveDNS: get reply from local, rtt: %dms", rtt.Milliseconds())
			if !forceLocal && !d.acceptLocalRes(res, requestLogger) {
				requestLogger.Debug("serveDNS: local result denied")
				close(localServerFailed)
				return
			}

			select {
			case resChan <- res:
			default:
			}
			close(localServerDone)
			requestLogger.Debug("serveDNS: local result accepted")
		}()
	}

	// remote
	if doRemote {
		wg.Add(1)
		go func() {
			defer wg.Done()

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
			res, rtt, err := d.queryRemote(q, requestLogger)
			if err != nil {
				requestLogger.Warnf("serveDNS: remote server failed: %v", err)
				return
			}
			requestLogger.Debugf("serveDNS: get reply from remote, rtt: %dms", rtt.Milliseconds())

			select {
			case resChan <- res:
			default:
			}
		}()
	}

	// watcher
	go func() {
		wg.Wait()
		close(serverFailedNotify)
	}()

	timeoutTimer := getTimer(queryTimeout)
	defer releaseTimer(timeoutTimer)

	select {
	case r := <-resChan:
		return r
	case <-serverFailedNotify:
		requestLogger.Warn("serveDNS: query failed: all servers failed")
		r := new(dns.Msg)
		r.SetReply(q)
		r.Rcode = dns.RcodeServerFailure
		return r
	case <-timeoutTimer.C:
		requestLogger.Warn("serveDNS: query failed: timeout")
		return nil
	}
}

func (d *dispatcher) queryLocal(q *dns.Msg, requestLogger *logrus.Entry) (*dns.Msg, time.Duration, error) {
	if d.localECS != nil {
		q = appendECSIfNotExist(q, d.localECS)
	}
	return d.localClient.Exchange(q, requestLogger)
}

//queryRemote WARNING: to save memory we may modify q directly.
func (d *dispatcher) queryRemote(q *dns.Msg, requestLogger *logrus.Entry) (*dns.Msg, time.Duration, error) {
	if d.remoteECS != nil {
		q = appendECSIfNotExist(q, d.remoteECS)
	}
	return d.remoteClient.Exchange(q, requestLogger)
}

// both q and ecs shouldn't be nil, the returned msg is a deep-copy if ecs is appended.
func appendECSIfNotExist(q *dns.Msg, ecs *dns.EDNS0_SUBNET) *dns.Msg {
	opt := q.IsEdns0()
	if opt == nil { // we need a new opt
		o := new(dns.OPT)
		o.SetUDPSize(4096) // TODO: is this big enough?
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.Option = []dns.EDNS0{ecs}
		qCopy := q.Copy()
		qCopy.Extra = append(qCopy.Extra, o)
		return qCopy
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
		return qCopy
	}

	return q
}

// check if local result is ok to accept, res can be nil.
func (d *dispatcher) acceptLocalRes(res *dns.Msg, requestLogger *logrus.Entry) (ok bool) {

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

	if len(res.Answer) == 0 {
		requestLogger.Debug("acceptLocalRes: false: empty answer")
		return false
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
	certPEMBlock, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %w", err)
	}

	cert, err := x509.ParseCertificate(certPEMBlock)
	if err != nil {
		return nil, fmt.Errorf("ParseCertificate: %w", err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(cert)
	return rootCAs, nil
}

func newClient(addr, prot, url, ca string) (upstream, error) {
	var client upstream
	switch prot {
	case "tcp", "udp", "":
		client = &upstreamTCPUDP{
			client: dns.Client{
				Timeout:        queryTimeout,
				UDPSize:        1480,
				Net:            prot,
				SingleInflight: false,
			},
			addr: addr,
		}
	case "doh":
		var rootCA *x509.CertPool
		var err error
		if len(ca) != 0 {
			rootCA, err = caPath2Pool(ca)
			if err != nil {
				return nil, fmt.Errorf("caPath2Pool: %w", err)
			}
		}
		tlsConf := &tls.Config{
			// don't have to set servername here, fasthttp will do it itself.
			RootCAs:            rootCA,
			ClientSessionCache: tls.NewLRUClientSessionCache(64),
		}

		if len(url) == 0 {
			return nil, fmt.Errorf("protocol [%s] needs URL", prot)
		}
		client = dohclient.NewClient(url, addr, tlsConf, dns.MaxMsgSize, queryTimeout)
	default:
		return nil, fmt.Errorf("unsupport protocol: %s", prot)
	}

	return client, nil
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
