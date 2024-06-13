package database

import (
	"fmt"
	"github.com/1f349/azalea/converters"
	"github.com/miekg/dns"
	"strings"
)

func (r Record) RR(defaultTtl uint32) (dns.RR, error) {
	header := dns.RR_Header{
		Name:   r.Name,
		Rrtype: dns.StringToType[r.Type],
		Class:  dns.ClassINET,
		Ttl:    defaultTtl,
	}
	if r.Ttl.Valid {
		header.Ttl = uint32(r.Ttl.Int64)
	}
	if header.Rrtype == dns.TypeNone {
		return nil, converters.ErrInvalidRecord{Name: r.Name, Value: r.Value, AType: r.Type, Reason: fmt.Errorf("invalid type %s", r.Type)}
	}

	// get data segments
	data := strings.Split(r.Value, "\t")
	if len(data) == 0 {
		return nil, converters.ErrInvalidRecord{Name: r.Name, Value: r.Value, AType: r.Type, Reason: converters.ErrInvalidSegmentCount}
	}
	rr, err := converters.Converters[header.Rrtype](data, header)
	if err != nil {
		return nil, converters.ErrInvalidRecord{Name: r.Name, Value: r.Value, AType: r.Type, Reason: err}
	}
	return rr, nil
}
