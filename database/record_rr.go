package database

import (
	"fmt"
	"github.com/1f349/azalea/converters"
	"github.com/1f349/azalea/utils"
	"github.com/miekg/dns"
	"strings"
)

func (r Record) RR(zone string, defaultTtl uint32) (dns.RR, error) {
	name := utils.ResolveRecordName(r.Name, zone)
	header := dns.RR_Header{
		Name:   name,
		Rrtype: dns.StringToType[r.Type],
		Class:  dns.ClassINET,
		Ttl:    defaultTtl,
	}
	if r.Ttl.Valid {
		header.Ttl = uint32(r.Ttl.Int64)
	}
	if header.Rrtype == dns.TypeNone {
		return nil, converters.ErrInvalidRecord{Name: name, Value: r.Value, AType: r.Type, Reason: fmt.Errorf("invalid type %s", r.Type)}
	}

	// get data segments
	data := strings.Split(r.Value, "\t")
	if len(data) == 0 {
		return nil, converters.ErrInvalidRecord{Name: name, Value: r.Value, AType: r.Type, Reason: converters.ErrInvalidSegmentCount}
	}
	rr, err := converters.Converters[header.Rrtype](data, header)
	if err != nil {
		return nil, converters.ErrInvalidRecord{Name: name, Value: r.Value, AType: r.Type, Reason: err}
	}
	return rr, nil
}

func (r Record) IsLocationResolving() bool {
	return r.Type == "LOC_RES"
}

func (r LookupRecordsForTypeRow) RR(defaultTtl uint32) (dns.RR, error) {
	return Record{
		ID:     r.ID,
		Zone:   r.Zone,
		Name:   r.Name,
		Type:   r.Type,
		Locked: r.Locked,
		Ttl:    r.Ttl,
		Value:  r.Value,
	}.RR(r.ZoneName, defaultTtl)
}

func (r LookupRecordsForTypeRow) IsLocationResolving() bool {
	return r.Type == "LOC_RES"
}
