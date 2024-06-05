package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/1f349/azalea/database"
	"github.com/1f349/azalea/logger"
	"github.com/charmbracelet/log"
	"github.com/miekg/dns"
	"strings"
	"sync"
)

type DnsServer struct {
	Addr   string
	conf   Conf
	db     *database.Queries
	srvUdp *dns.Server
	srvTcp *dns.Server
	mu     *sync.RWMutex
	mem    map[string]map[uint16]dns.RR
	rExtra []dns.RR
}

func (d *DnsServer) Run() {
	err := d.Reload(context.Background())
	if err != nil {
		logger.Logger.Warn("Failed to reload", "err", err)
	}
	go runBackgroundDns(logger.Logger, d.srvUdp)
	go runBackgroundDns(logger.Logger, d.srvTcp)
}

func runBackgroundDns(logger *log.Logger, d *dns.Server) {
	err := d.ListenAndServe()
	if err != nil {
		logger.Info("Error trying to host the dns server", "net", d.Net, "err", err)
	}
}

func (d *DnsServer) Close() error {
	return errors.Join(d.srvUdp.Shutdown(), d.srvTcp.Shutdown())
}

func (d *DnsServer) Reload(ctx context.Context) error {
	mem := make(map[string]map[uint16]dns.RR)
	setRr := func(name string, rrType uint16, rr dns.RR) {
		if mem[name] == nil {
			mem[name] = make(map[uint16]dns.RR)
		}
		mem[name][rrType] = rr
	}
	rSoa, err := d.db.GetAllSoaRecords(ctx)
	if err != nil {
		return err
	}
	for _, i := range rSoa {
		setRr(i.Name, dns.TypeSOA, &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   i.Name,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    uint32(i.Ttl),
			},
			Ns:      i.Ns,
			Mbox:    i.Mbox,
			Serial:  uint32(i.Serial),
			Refresh: uint32(i.Refresh),
			Retry:   uint32(i.Retry),
			Expire:  uint32(i.Expire),
			Minttl:  uint32(i.Ttl),
		})
	}
	rA, err := d.db.GetAllARecords(ctx)
	if err != nil {
		return err
	}
	for _, i := range rA {
		setRr(i.Name, dns.TypeA, &dns.A{
			Hdr: dns.RR_Header{
				Name:   i.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(i.Ttl),
			},
			A: i.Value,
		})
	}
	rAAAA, err := d.db.GetAllAAAARecords(ctx)
	if err != nil {
		return err
	}
	for _, i := range rAAAA {
		setRr(i.Name, dns.TypeAAAA, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   i.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    uint32(i.Ttl),
			},
			AAAA: i.Value,
		})
	}
	rCname, err := d.db.GetAllCnameRecords(ctx)
	if err != nil {
		return err
	}
	for _, i := range rCname {
		setRr(i.Name, dns.TypeCNAME, &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   i.Name,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    uint32(i.Ttl),
			},
			Target: i.Value,
		})
	}
	rMx, err := d.db.GetAllMxRecords(ctx)
	if err != nil {
		return err
	}
	for _, i := range rMx {
		setRr(i.Name, dns.TypeMX, &dns.MX{
			Hdr: dns.RR_Header{
				Name:   i.Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    uint32(i.Ttl),
			},
			Preference: uint16(i.Priority),
			Mx:         i.Value,
		})
	}
	rTxt, err := d.db.GetAllTxtRecords(ctx)
	if err != nil {
		return err
	}
	for _, i := range rTxt {
		var a []string
		err := json.Unmarshal([]byte(i.Value), &a)
		if err != nil {
			return err
		}
		setRr(i.Name, dns.TypeTXT, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   i.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    uint32(i.Ttl),
			},
			Txt: a,
		})
	}
	rSrv, err := d.db.GetAllSrvRecords(ctx)
	if err != nil {
		return err
	}
	for _, i := range rSrv {
		setRr(i.Name, dns.TypeSRV, &dns.SRV{
			Hdr: dns.RR_Header{
				Name:   i.Name,
				Rrtype: dns.TypeSRV,
				Class:  dns.ClassINET,
				Ttl:    uint32(i.Ttl),
			},
			Priority: uint16(i.Priority),
			Weight:   uint16(i.Weight),
			Port:     uint16(i.Port),
			Target:   i.Target,
		})
	}
	d.mu.Lock()
	d.mem = mem
	d.mu.Unlock()
	return nil
}

func (d *DnsServer) resolver(name string, qType uint16) []dns.RR {
	logger.Logger.Warn("resolver", "name", name)
	rr := make([]dns.RR, 0, 1)
	m := d.recursiveDomainResolution(name)
	if m != nil {
		a := m[qType]
		if a != nil {
			rr = append(rr, m[qType])
		}
	}
	return rr
}

func (d *DnsServer) resolveNameservers(domain string) []dns.RR {
	rr := make([]dns.RR, len(d.conf.Ns))
	for i, v := range d.conf.Ns {
		rr[i] = &dns.NS{
			Hdr: dns.RR_Header{
				Name:   domain,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    d.conf.NsTtl,
			},
			Ns: v,
		}
	}
	return rr
}

func (d *DnsServer) recursiveDomainResolution(host string) map[uint16]dns.RR {
	a, ok := d.mem[host]
	if ok {
		return a
	}
	n := strings.IndexByte(host, '.')
	if n == -1 {
		return nil
	}
	host = "*" + host[n:]
	return d.mem[host]
}

func (d *DnsServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	fmt.Println("Received message")

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	msg.Ns = d.resolveNameservers(r.Question[0].Name)
	msg.Extra = d.rExtra

	for _, question := range r.Question {
		answers := d.resolver(question.Name, question.Qtype)
		msg.Answer = append(msg.Answer, answers...)
	}

	err := w.WriteMsg(msg)
	logger.Logger.Warn(err)
}

func NewDnsServer(conf Conf, db *database.Queries) *DnsServer {
	d := &DnsServer{
		Addr: conf.Listen,
		conf: conf,
		db:   db,
		mu:   new(sync.RWMutex),
		mem:  make(map[string]map[uint16]dns.RR),
	}

	// setup additional section with nameserver IPs
	d.rExtra = make([]dns.RR, len(conf.Extra))
	for i, v := range conf.Extra {
		t := dns.StringToType[v.Type]
		switch t {
		case dns.TypeA:
			d.rExtra[i] = &dns.A{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: t,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				A: v.Value,
			}
		case dns.TypeAAAA:
			d.rExtra[i] = &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   v.Name,
					Rrtype: t,
					Class:  dns.ClassINET,
					Ttl:    v.Ttl,
				},
				AAAA: v.Value,
			}
		default:
			logger.Logger.Fatal("Invalid extra type", "type", v.Type)
		}
	}

	d.srvUdp = &dns.Server{
		Addr:      conf.Listen,
		Net:       "udp",
		Handler:   d,
		UDPSize:   65535,
		ReusePort: true,
		ReuseAddr: true,
	}
	d.srvTcp = &dns.Server{
		Addr:      conf.Listen,
		Net:       "tcp",
		Handler:   d,
		ReusePort: true,
		ReuseAddr: true,
	}
	return d
}
