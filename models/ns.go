package models

import (
	"encoding/json"
	"errors"
	"github.com/miekg/dns"
)

var _ json.Marshaler = (*NS)(nil)
var _ json.Unmarshaler = (*NS)(nil)

type NS struct {
	Ns string
}

func (ns NS) MarshalJSON() ([]byte, error) {
	return json.Marshal(ns.Ns)
}

func (ns *NS) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, &ns.Ns)
	if err != nil {
		return err
	}
	if _, ok := dns.IsDomainName(ns.Ns); !ok {
		return errors.New("invalid MX value")
	}
	ns.Ns = dns.Fqdn(ns.Ns)
	return nil
}

func (ns NS) ValueRR(header dns.RR_Header) dns.RR {
	return &dns.NS{
		Hdr: header,
		Ns:  ns.Ns,
	}
}

func (ns NS) ValueType() uint16 {
	return dns.TypeNS
}

func (ns NS) EncodeValue() string {
	return ns.Ns
}
