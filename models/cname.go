package models

import (
	"encoding/json"
	"errors"
	"github.com/miekg/dns"
)

var _ json.Marshaler = (*CNAME)(nil)
var _ json.Unmarshaler = (*CNAME)(nil)

type CNAME struct {
	Target string
}

func (cname CNAME) MarshalJSON() ([]byte, error) {
	return json.Marshal(dns.Fqdn(cname.Target))
}

func (cname *CNAME) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, &cname.Target)
	if err != nil {
		return err
	}
	if _, ok := dns.IsDomainName(cname.Target); !ok {
		return errors.New("invalid MX value")
	}
	cname.Target = dns.Fqdn(cname.Target)
	return nil
}

func (cname CNAME) ValueRR(header dns.RR_Header) dns.RR {
	return &dns.CNAME{
		Hdr:    header,
		Target: cname.Target,
	}
}

func (cname CNAME) ValueType() uint16 {
	return dns.TypeCNAME
}

func (cname CNAME) EncodeValue() string {
	return cname.Target
}
