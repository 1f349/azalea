package models

import (
	"encoding/json"
	"errors"
	"github.com/miekg/dns"
	"net"
	"net/netip"
)

var _ json.Marshaler = (*A)(nil)
var _ json.Unmarshaler = (*A)(nil)

type A struct {
	net.IP
}

func (a A) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.IP)
}

func (a *A) UnmarshalJSON(bytes []byte) error {
	var ip netip.Addr
	err := json.Unmarshal(bytes, &ip)
	if err != nil {
		return err
	}
	if ip.Zone() != "" {
		return errors.New("zones are not supported")
	}
	if !ip.Is4() {
		return errors.New("not an IPv4 address")
	}
	a.IP = ip.AsSlice()
	return nil
}

func (a A) ValueRR(header dns.RR_Header) dns.RR {
	return &dns.A{
		Hdr: header,
		A:   a.IP,
	}
}

func (a A) ValueType() uint16 {
	return dns.TypeA
}

func (a A) EncodeValue() string {
	return a.IP.String()
}
