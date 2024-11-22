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

const maxSplitTxtSize = 255

func splitTxtValue(s string) []string {
	// exception for empty string rule
	if s == "" {
		return []string{""}
	}

	// calculate the expected number of items
	lenS := len(s)
	expected := lenS / maxSplitTxtSize
	if len(s)%maxSplitTxtSize > 0 {
		expected++
	}

	// construct the slice
	a := make([]string, expected)
	for i := 0; i < expected; i++ {
		j := i * maxSplitTxtSize
		end := min(j+maxSplitTxtSize, lenS)
		a[i] = s[j:end]
	}
	return a
}
