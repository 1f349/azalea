package server

import (
	"github.com/1f349/azalea/database"
	"github.com/256dpi/newdns"
	"sync"
)

type Zone struct {
	db   *database.Queries
	zone *newdns.Zone
	mu   *sync.RWMutex
	mem  map[string][]newdns.Set
}

func NewZone(server *DnsServer, db *database.Queries, conf Conf, name string) *Zone {
	// create zone
	return &Zone{
		db: db,
		zone: &newdns.Zone{
			Name:             name,
			MasterNameServer: conf.Ns[0],
			AllNameServers:   conf.Ns,
			Handler: func(name string) ([]newdns.Set, error) {
				// return apex records
				if name == "" {
					return []newdns.Set{
						{
							Name: "1f349.com.",
							Type: newdns.A,
							Records: []newdns.Record{
								{Address: "1.2.3.4"},
								{Address: "5.6.7.8"},
							},
						},
						{
							Name: "1f349.com.",
							Type: newdns.AAAA,
							Records: []newdns.Record{
								{Address: "1:2:3:4::"},
							},
						},
					}, nil
				}

				// return sub records
				if name == "foo" {
					return []newdns.Set{
						{
							Name: "foo.example.com.",
							Type: newdns.CNAME,
							Records: []newdns.Record{
								{Address: "bar.example.com."},
							},
						},
					}, nil
				}

				return nil, nil
			},
		},
		mu:  new(sync.RWMutex),
		mem: make(map[string][]newdns.Set),
	}
}

func (z *Zone) Handler(name string) ([]newdns.Set, error) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.mem[name], nil
}

//func (d *DnsServer) recursiveDomainResolution(host string) map[uint16]dns.RR {
//	a, ok := d.mem[host]
//	if ok {
//		return a
//	}
//	n := strings.IndexByte(host, '.')
//	if n == -1 {
//		return nil
//	}
//	host = "*" + host[n:]
//	return d.mem[host]
//}

//func (d *DnsServer) Reload(ctx context.Context) error {
//	mem := make(map[string]map[uint16]dns.RR)
//	setRr := func(name string, rrType uint16, rr dns.RR) {
//		if mem[name] == nil {
//			mem[name] = make(map[uint16]dns.RR)
//		}
//		mem[name][rrType] = rr
//	}
//	rSoa, err := d.db.GetAllSoaRecords(ctx)
//	if err != nil {
//		return err
//	}
//	for _, i := range rSoa {
//		setRr(i.Name, dns.TypeSOA, &dns.SOA{
//			Hdr: dns.RR_Header{
//				Name:   i.Name,
//				Rrtype: dns.TypeSOA,
//				Class:  dns.ClassINET,
//				Ttl:    uint32(i.Ttl),
//			},
//			Ns:      i.Ns,
//			Mbox:    i.Mbox,
//			Serial:  uint32(i.Serial),
//			Refresh: uint32(i.Refresh),
//			Retry:   uint32(i.Retry),
//			Expire:  uint32(i.Expire),
//			Minttl:  uint32(i.Ttl),
//		})
//	}
//	rA, err := d.db.GetAllARecords(ctx)
//	if err != nil {
//		return err
//	}
//	for _, i := range rA {
//		setRr(i.Name, dns.TypeA, &dns.A{
//			Hdr: dns.RR_Header{
//				Name:   i.Name,
//				Rrtype: dns.TypeA,
//				Class:  dns.ClassINET,
//				Ttl:    uint32(i.Ttl),
//			},
//			A: i.Value,
//		})
//	}
//	rAAAA, err := d.db.GetAllAAAARecords(ctx)
//	if err != nil {
//		return err
//	}
//	for _, i := range rAAAA {
//		setRr(i.Name, dns.TypeAAAA, &dns.AAAA{
//			Hdr: dns.RR_Header{
//				Name:   i.Name,
//				Rrtype: dns.TypeAAAA,
//				Class:  dns.ClassINET,
//				Ttl:    uint32(i.Ttl),
//			},
//			AAAA: i.Value,
//		})
//	}
//	rCname, err := d.db.GetAllCnameRecords(ctx)
//	if err != nil {
//		return err
//	}
//	for _, i := range rCname {
//		setRr(i.Name, dns.TypeCNAME, &dns.CNAME{
//			Hdr: dns.RR_Header{
//				Name:   i.Name,
//				Rrtype: dns.TypeCNAME,
//				Class:  dns.ClassINET,
//				Ttl:    uint32(i.Ttl),
//			},
//			Target: i.Value,
//		})
//	}
//	rMx, err := d.db.GetAllMxRecords(ctx)
//	if err != nil {
//		return err
//	}
//	for _, i := range rMx {
//		setRr(i.Name, dns.TypeMX, &dns.MX{
//			Hdr: dns.RR_Header{
//				Name:   i.Name,
//				Rrtype: dns.TypeMX,
//				Class:  dns.ClassINET,
//				Ttl:    uint32(i.Ttl),
//			},
//			Preference: uint16(i.Priority),
//			Mx:         i.Value,
//		})
//	}
//	rTxt, err := d.db.GetAllTxtRecords(ctx)
//	if err != nil {
//		return err
//	}
//	for _, i := range rTxt {
//		var a []string
//		err := json.Unmarshal([]byte(i.Value), &a)
//		if err != nil {
//			return err
//		}
//		setRr(i.Name, dns.TypeTXT, &dns.TXT{
//			Hdr: dns.RR_Header{
//				Name:   i.Name,
//				Rrtype: dns.TypeTXT,
//				Class:  dns.ClassINET,
//				Ttl:    uint32(i.Ttl),
//			},
//			Txt: a,
//		})
//	}
//	rSrv, err := d.db.GetAllSrvRecords(ctx)
//	if err != nil {
//		return err
//	}
//	for _, i := range rSrv {
//		setRr(i.Name, dns.TypeSRV, &dns.SRV{
//			Hdr: dns.RR_Header{
//				Name:   i.Name,
//				Rrtype: dns.TypeSRV,
//				Class:  dns.ClassINET,
//				Ttl:    uint32(i.Ttl),
//			},
//			Priority: uint16(i.Priority),
//			Weight:   uint16(i.Weight),
//			Port:     uint16(i.Port),
//			Target:   i.Target,
//		})
//	}
//	d.mu.Lock()
//	d.mem = mem
//	d.mu.Unlock()
//	return nil
//}
