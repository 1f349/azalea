package models

import (
	"encoding/json"
	"errors"
	"github.com/miekg/dns"
	"net"
	"net/netip"
)

var _ json.Marshaler = (*AAAA)(nil)
var _ json.Unmarshaler = (*AAAA)(nil)

type AAAA struct {
	net.IP
}

func (aaaa AAAA) MarshalJSON() ([]byte, error) {
	return json.Marshal(aaaa.IP)
}

func (aaaa *AAAA) UnmarshalJSON(bytes []byte) error {
	var ip netip.Addr
	err := json.Unmarshal(bytes, &ip)
	if err != nil {
		return err
	}
	if ip.Zone() != "" {
		return errors.New("zones are not supported")
	}
	if !ip.Is6() {
		return errors.New("not an IPv6 address")
	}
	aaaa.IP = ip.AsSlice()
	return nil
}

func (aaaa AAAA) ValueRR(header dns.RR_Header) dns.RR {
	return &dns.AAAA{
		Hdr:  header,
		AAAA: aaaa.IP,
	}
}

func (aaaa AAAA) ValueType() uint16 {
	return dns.TypeAAAA
}

func (aaaa AAAA) EncodeValue() string {
	return aaaa.IP.String()
}
