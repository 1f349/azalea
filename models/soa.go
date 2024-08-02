package models

import (
	"fmt"
	"github.com/miekg/dns"
)

type SOA struct {
	Ns      string `json:"ns"`
	Mbox    string `json:"mbox"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minttl  uint32 `json:"minttl"`
}

func (soa SOA) ValueRR(header dns.RR_Header) dns.RR {
	return &dns.SOA{
		Hdr:     header,
		Ns:      soa.Ns,
		Mbox:    soa.Mbox,
		Serial:  soa.Serial,
		Refresh: soa.Refresh,
		Retry:   soa.Retry,
		Expire:  soa.Expire,
		Minttl:  soa.Minttl,
	}
}

func (soa SOA) ValueType() uint16 {
	return dns.TypeSOA
}

func (soa SOA) EncodeValue() string {
	return fmt.Sprintf("%s\t%s\t%d\t%d\t%d\t%d\t%d", soa.Ns, soa.Mbox, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minttl)
}
