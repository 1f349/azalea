package models

import (
	"encoding/json"
	"github.com/miekg/dns"
)

var _ json.Marshaler = (*TXT)(nil)
var _ json.Unmarshaler = (*TXT)(nil)

type TXT struct {
	Value string
}

func (txt TXT) MarshalJSON() ([]byte, error) {
	return json.Marshal(txt.Value)
}

func (txt *TXT) UnmarshalJSON(bytes []byte) error {
	return json.Unmarshal(bytes, &txt.Value)
}

func (txt TXT) ValueRR(header dns.RR_Header) dns.RR {
	return &dns.TXT{
		Hdr: header,
		Txt: []string{txt.Value},
	}
}

func (txt TXT) ValueType() uint16 {
	return dns.TypeAAAA
}

func (txt TXT) EncodeValue() string {
	return txt.Value
}
