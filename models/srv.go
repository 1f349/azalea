package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/miekg/dns"
)

var _ json.Unmarshaler = (*SRV)(nil)

type SRV struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}

func (srv *SRV) UnmarshalJSON(bytes []byte) error {
	type inner SRV
	var a inner
	err := json.Unmarshal(bytes, &a)
	if err != nil {
		return err
	}
	*srv = SRV(a)
	if _, ok := dns.IsDomainName(srv.Target); !ok {
		return errors.New("invalid MX value")
	}
	srv.Target = dns.Fqdn(srv.Target)
	return nil
}

func (srv SRV) ValueRR(header dns.RR_Header) dns.RR {
	return &dns.SRV{
		Hdr:      header,
		Priority: srv.Priority,
		Weight:   srv.Weight,
		Port:     srv.Port,
		Target:   srv.Target,
	}
}

func (srv SRV) ValueType() uint16 {
	return dns.TypeSRV
}

func (srv SRV) EncodeValue() string {
	return fmt.Sprintf("%d\t%d\t%d\t%s", srv.Priority, srv.Weight, srv.Port, srv.Target)
}
