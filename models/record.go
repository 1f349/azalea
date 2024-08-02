package models

import (
	"github.com/gobuffalo/nulls"
	"github.com/miekg/dns"
)

const StaticSoaRecord = -1
const StaticNsRecord = -2
const DynamicRecords = -3

type Record struct {
	Id    int64        `json:"id"`
	Name  string       `json:"name"`
	Type  uint16       `json:"type"`
	Ttl   nulls.UInt32 `json:"ttl"`
	Value RecordValue  `json:"value"`
}

func (r Record) RR(ttl uint32) dns.RR {
	return r.Value.ValueRR(dns.RR_Header{
		Name:   r.Name,
		Rrtype: r.Type,
		Class:  dns.ClassINET,
		Ttl:    ttl,
	})
}

type RecordValue interface {
	ValueRR(header dns.RR_Header) dns.RR
	ValueType() uint16
	EncodeValue() string
}
