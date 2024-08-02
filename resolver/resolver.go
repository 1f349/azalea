package resolver

import (
	"context"
	"fmt"
	"github.com/1f349/azalea/conf"
	"github.com/1f349/azalea/converters"
	"github.com/1f349/azalea/database"
	"github.com/1f349/azalea/logger"
	"github.com/1f349/azalea/models"
	"github.com/1f349/azalea/utils"
	"github.com/miekg/dns"
	"github.com/rcrowley/go-metrics"
	"golang.org/x/net/publicsuffix"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type Resolver struct {
	soa     conf.SoaConf
	db      *database.Queries
	zoneMu  *sync.RWMutex
	zoneMap map[int64]string
	geo     *GeoResolver
}

func NewResolver(soa conf.SoaConf, db *database.Queries, geo *GeoResolver) *Resolver {
	return &Resolver{
		soa:     soa,
		db:      db,
		zoneMu:  new(sync.RWMutex),
		zoneMap: make(map[int64]string),
		geo:     geo,
	}
}

func (r *Resolver) Authority(ctx context.Context, domain string) (soa *models.Record) {
	tree := strings.Split(domain, ".")
	for i, _ := range tree {
		subdomain := strings.Join(tree[i:], ".")

		answers, err := r.LookupAnswersForType(ctx, subdomain, dns.TypeSOA, nil)
		if err != nil {
			return
		}

		if len(answers) == 1 {
			soa = answers[0]
			return
		}
	}

	missingCounter := metrics.GetOrRegisterCounter("resolver.authority.missing_soa", metrics.DefaultRegistry)
	missingCounter.Inc(1)
	return
}

func (r *Resolver) Lookup(ctx context.Context, req *dns.Msg, addr net.Addr) (msg *dns.Msg) {
	q := req.Question[0]

	msg = new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true
	msg.RecursionAvailable = false

	var answers []*models.Record
	var errors []error
	errored := false

	var aChan chan *models.Record
	var eChan chan error

	if q.Qclass == dns.ClassINET {
		aChan, eChan = r.AnswerQuestion(ctx, q, addr)
		answers, errors = gatherFromChannels(aChan, eChan)
	}

	errored = len(errors) > 0
	if len(answers) == 0 {
		// If we failed to find any answers, let's keep looking up the tree for
		// any wildcard domain entries.
		parts := strings.Split(q.Name, ".")
		for level := 1; level < len(parts); level++ {
			domain := strings.Join(parts[level:], ".")
			if len(domain) > 1 {
				question := dns.Question{
					Name:   "*." + dns.Fqdn(domain),
					Qtype:  q.Qtype,
					Qclass: q.Qclass}

				aChan, eChan = r.AnswerQuestion(ctx, question, addr)
				answers, errors = gatherFromChannels(aChan, eChan)

				errored = errored || len(errors) > 0
				if len(answers) > 0 {
					break
				}
			}
		}
	}

	missCounter := metrics.GetOrRegisterCounter("resolver.answers.miss", metrics.DefaultRegistry)
	hitCounter := metrics.GetOrRegisterCounter("resolver.answers.hit", metrics.DefaultRegistry)
	errorCounter := metrics.GetOrRegisterCounter("resolver.answers.error", metrics.DefaultRegistry)

	if errored {
		// TODO(tarnfeld): Send special TXT records with a server error response code
		errorCounter.Inc(1)
		msg.SetRcode(req, dns.RcodeServerFailure)
	} else if len(answers) == 0 {
		soa := r.Authority(ctx, q.Name)
		missCounter.Inc(1)
		msg.SetRcode(req, dns.RcodeNameError)
		if soa != nil {
			msg.Ns = []dns.RR{soa.RR(300)} // TODO(melon): per domain default ttl
		} else {
			msg.Authoritative = false // No SOA? We're not authoritative
		}
	} else {
		hitCounter.Inc(1)
		for _, record := range answers {
			rr := record.RR(300)
			rr.Header().Name = q.Name
			msg.Answer = append(msg.Answer, rr) // TODO(melon): per domain default ttl
		}
	}

	return
}

func gatherFromChannels(rrsIn chan *models.Record, errsIn chan error) (rrs []*models.Record, errs []error) {
	rrs = []*models.Record{}
	errs = []error{}
	done := 0
	for done < 2 {
		select {
		case rr, ok := <-rrsIn:
			if ok {
				rrs = append(rrs, rr)
			} else {
				done++
			}
		case err, ok := <-errsIn:
			if ok {
				logger.Logger.Error("Caught error", "err", err)
				errs = append(errs, err)
			} else {
				done++
			}
		}
	}
	return rrs, errs
}

// AnswerQuestion takes two channels, one for answers and one for errors. It will answer the
// given question writing the answers as dns.RR structures, and any errors it encounters along
// the way. The function will return immediately, and spawn off a bunch of goroutines
// to do the work, when using this function one should use a WaitGroup to know when all work
// has been completed.
func (r *Resolver) AnswerQuestion(ctx context.Context, q dns.Question, addr net.Addr) (answers chan *models.Record, errors chan error) {
	answers = make(chan *models.Record)
	errors = make(chan error)

	typeStr := dns.TypeToString[q.Qtype]
	typeCounter := metrics.GetOrRegisterCounter("resolver.answers.type."+typeStr, metrics.DefaultRegistry)
	typeCounter.Inc(1)
	questionCounter := metrics.GetOrRegisterCounter("resolver.answers.question."+typeStr+"."+q.Name, metrics.DefaultRegistry)
	questionCounter.Inc(1)

	logger.Logger.Debug("Answering question ", "q", q)

	if _, ok := converters.Converters[q.Qtype]; ok {
		go func() {
			defer func() {
				close(answers)
				close(errors)
			}()
			records, err := r.LookupAnswersForType(ctx, q.Name, q.Qtype, addr)
			if err != nil {
				errors <- err
			} else {
				if len(records) > 0 {
					for _, rr := range records {
						answers <- rr
					}
				} else {
					cnames, err := r.LookupAnswersForType(ctx, q.Name, dns.TypeCNAME, nil)
					if err != nil {
						errors <- err
					} else {
						if len(cnames) > 1 {
							errors <- fmt.Errorf("multiple CNAME records is invalid")
						} else if len(cnames) > 0 {
							answers <- cnames[0]
						}
					}
				}
			}
		}()
	} else {
		// nothing we can do
		close(answers)
		close(errors)
	}

	return answers, errors
}

func (r *Resolver) LookupAnswersForType(ctx context.Context, name string, rrType uint16, addr net.Addr) (answers []*models.Record, err error) {
	name = strings.ToLower(name)

	switch rrType {
	case dns.TypeSOA:
		record := r.getSoaRecord(name)
		return []*models.Record{record}, nil
	case dns.TypeNS:
		records := r.getNsRecords(name)
		if len(records) == 0 {
			return records, nil
		}

		// randomise which NS record shows first
		n := rand.IntN(len(records))
		records[0], records[n] = records[n], records[0]
		return records, nil
	}

	rootZone, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(name, "."))
	if err != nil {
		return nil, err
	}
	shortName := utils.SimplifyRecordName(name, dns.Fqdn(rootZone))

	records, err := r.db.LookupRecordsForType(ctx, database.LookupRecordsForTypeParams{Type: dns.TypeToString[rrType], Name: shortName, Name_2: dns.Fqdn(rootZone)})
	if err != nil {
		return nil, err
	}

	// convert records to dns.RR and process location resolving records
	rrs := make([]*models.Record, 0, len(records))
	for _, record := range records {
		if record.IsLocationResolving() {
			if addr != nil {
				// parse the ip address and resolve
				addrPort, err := netip.ParseAddrPort(addr.String())
				if err != nil {
					return nil, err
				}
				resolvedRecords, err := r.geo.GeoResolvedRecords(ctx, record.Value, addrPort.Addr().AsSlice())
				if err != nil {
					return nil, err
				}
				rrs = append(rrs, resolvedRecords...)
			}
			continue
		}
		// convert to an RR record
		rr, err := record.ConvertRecord()
		if err != nil {
			return nil, err
		}
		rrs = append(rrs, rr)
	}

	return rrs, nil
}

func (r *Resolver) GetAllRecords(ctx context.Context) ([]*models.Record, error) {
	zones, err := r.db.GetZones(ctx)
	if err != nil {
		return nil, err
	}

	rrs := make([]*models.Record, 0)
	for _, i := range zones {
		zoneRecords, err := r.GetZoneRecords(ctx, i.Name)
		if err != nil {
			return nil, err
		}
		rrs = append(rrs, zoneRecords...)
	}

	return rrs, nil
}

func (r *Resolver) GetZoneRecords(ctx context.Context, zone string) ([]*models.Record, error) {
	_, err := r.db.GetZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	records, err := r.db.GetZoneRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	rrs := make([]*models.Record, 0, len(records)+1+len(r.soa.Ns)) // preallocate for all records
	rrs = append(rrs, r.getSoaRecord(zone))
	rrs = append(rrs, r.getNsRecords(zone)...)

	for _, i := range records {
		if i.IsLocationResolving() {
			name := utils.ResolveRecordName(i.Name, zone)
			rrs = append(rrs, &models.Record{
				Name: "_loc_res." + name,
				Type: dns.TypeTXT,
				Value: &models.TXT{
					Value: i.Value,
				},
			})
			continue
		}
		rr, err := i.ConvertRecord(zone)
		if err != nil {
			return nil, err
		}
		rrs = append(rrs, rr)
	}

	return rrs, nil
}

func (r *Resolver) getSoaRecord(zone string) *models.Record {
	n := time.Now()
	year, month, day := n.Date()
	n2 := uint32(year*1e6 + int(month*1e4) + day*1e2 + 01)

	rootZone, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(zone, "."))
	if err != nil {
		return nil
	}

	return &models.Record{
		Name: dns.Fqdn(rootZone),
		Type: dns.TypeSOA,
		Value: &models.SOA{
			Ns:      dns.Fqdn(r.soa.Ns[0]),
			Mbox:    dns.Fqdn(r.soa.Mbox),
			Serial:  n2,
			Refresh: r.soa.Refresh,
			Retry:   r.soa.Retry,
			Expire:  r.soa.Expire,
			Minttl:  r.soa.Ttl,
		},
	}
}

func (r *Resolver) getNsRecords(zone string) []*models.Record {
	rrs := make([]*models.Record, 0, len(r.soa.Ns))
	for _, ns := range r.soa.Ns {
		rrs = append(rrs, &models.Record{
			Name: zone,
			Type: dns.TypeNS,
			Value: &models.NS{
				Ns: dns.Fqdn(ns),
			},
		})
	}
	return rrs
}
