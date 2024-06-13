package server

import (
	"context"
	"fmt"
	"github.com/1f349/azalea/converters"
	"github.com/1f349/azalea/database"
	"github.com/1f349/azalea/logger"
	"github.com/miekg/dns"
	"github.com/rcrowley/go-metrics"
	"strings"
	"sync"
)

type Resolver struct {
	db         *database.Queries
	defaultTtl uint32
	mu         *sync.RWMutex
	records    map[string]map[uint16][]dns.RR
}

func NewResolver(db *database.Queries) *Resolver {
	return &Resolver{
		db:         db,
		defaultTtl: 300,
		mu:         &sync.RWMutex{},
		records:    make(map[string]map[uint16][]dns.RR),
	}
}

func (r *Resolver) Reload(ctx context.Context) error {
	records := make(map[string]map[uint16][]dns.RR)

	allRecords, err := r.db.GetAllRecords(ctx)
	if err != nil {
		return err
	}
	for _, i := range allRecords {
		rr, err := i.RR(r.defaultTtl)
		if err != nil {
			return err
		}
		setRecord(records, i.Name, rr)
	}

	r.mu.Lock()
	r.records = records
	r.mu.Unlock()

	return nil
}

func setRecord(records map[string]map[uint16][]dns.RR, name string, rr dns.RR) {
	if records[name] == nil {
		records[name] = make(map[uint16][]dns.RR)
	}
	if records[name][rr.Header().Rrtype] == nil {
		records[name][rr.Header().Rrtype] = make([]dns.RR, 0)
	}
	records[name][rr.Header().Rrtype] = append(records[name][rr.Header().Rrtype], rr)
}

func (r *Resolver) Authority(domain string) (soa *dns.SOA) {
	tree := strings.Split(domain, ".")
	for i, _ := range tree {
		subdomain := strings.Join(tree[i:], ".")

		answers, err := r.LookupAnswersForType(subdomain, dns.TypeSOA)
		if err != nil {
			return
		}

		if len(answers) == 1 {
			soa = answers[0].(*dns.SOA)
			return
		}
	}

	missingCounter := metrics.GetOrRegisterCounter("resolver.authority.missing_soa", metrics.DefaultRegistry)
	missingCounter.Inc(1)
	return
}

func (r *Resolver) Lookup(req *dns.Msg) (msg *dns.Msg) {
	q := req.Question[0]

	msg = new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true
	msg.RecursionAvailable = false

	var answers []dns.RR
	var errors []error
	errored := false

	var aChan chan dns.RR
	var eChan chan error

	if q.Qclass == dns.ClassINET {
		aChan, eChan = r.AnswerQuestion(q)
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

				aChan, eChan = r.AnswerQuestion(question)
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
		soa := r.Authority(q.Name)
		missCounter.Inc(1)
		msg.SetRcode(req, dns.RcodeNameError)
		if soa != nil {
			msg.Ns = []dns.RR{soa}
		} else {
			msg.Authoritative = false // No SOA? We're not authoritative
		}
	} else {
		hitCounter.Inc(1)
		for _, rr := range answers {
			rr.Header().Name = q.Name
			msg.Answer = append(msg.Answer, rr)
		}
	}

	return
}

func gatherFromChannels(rrsIn chan dns.RR, errsIn chan error) (rrs []dns.RR, errs []error) {
	rrs = []dns.RR{}
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
func (r *Resolver) AnswerQuestion(q dns.Question) (answers chan dns.RR, errors chan error) {
	answers = make(chan dns.RR)
	errors = make(chan error)

	typeStr := strings.ToLower(dns.TypeToString[q.Qtype])
	typeCounter := metrics.GetOrRegisterCounter("resolver.answers.type."+typeStr, metrics.DefaultRegistry)
	typeCounter.Inc(1)

	logger.Logger.Debug("Answering question ", "q", q)

	if _, ok := converters.Converters[q.Qtype]; ok {
		go func() {
			defer func() {
				close(answers)
				close(errors)
			}()
			records, err := r.LookupAnswersForType(q.Name, q.Qtype)
			if err != nil {
				errors <- err
			} else {
				if len(records) > 0 {
					for _, rr := range records {
						answers <- rr
					}
				} else {
					cnames, err := r.LookupAnswersForType(q.Name, dns.TypeCNAME)
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

func (r *Resolver) LookupAnswersForType(name string, rrType uint16) (answers []dns.RR, err error) {
	name = strings.ToLower(name)

	r.mu.RLock()
	defer r.mu.RUnlock()

	layer, ok := r.records[name]
	if !ok {
		return nil, nil
	}
	layer2, ok := layer[rrType]
	if !ok {
		return nil, nil
	}
	return layer2, nil
}
