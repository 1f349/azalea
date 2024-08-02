package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/miekg/dns"
)

var _ json.Unmarshaler = (*MX)(nil)

type MX struct {
	Preference uint16 `json:"preference"`
	Mx         string `json:"mx"`
}

func (mx *MX) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, mx)
	if err != nil {
		return err
	}
	if _, ok := dns.IsDomainName(mx.Mx); !ok {
		return errors.New("invalid MX value")
	}
	mx.Mx = dns.Fqdn(mx.Mx)
	return nil
}

func (mx MX) ValueRR(header dns.RR_Header) dns.RR {
	return &dns.MX{
		Hdr:        header,
		Preference: mx.Preference,
		Mx:         mx.Mx,
	}
}

func (mx MX) ValueType() uint16 {
	return dns.TypeMX
}

func (mx MX) EncodeValue() string {
	return fmt.Sprintf("%d\t%s", mx.Preference, mx.Mx)
}
