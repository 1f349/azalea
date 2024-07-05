package converters

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strconv"
)

type ErrInvalidRecord struct {
	Name   string
	Value  string
	AType  string
	Reason error
}

func (e ErrInvalidRecord) Error() string {
	return fmt.Sprintf("invalid record: name='%s', type='%s', value='%s' because %s", e.Name, e.AType, e.Value, e.Reason)
}

func (e ErrInvalidRecord) Unwrap() error {
	return e.Reason
}

var ErrInvalidSegmentCount = errors.New("invalid segment count")

var Converters = map[uint16]func(data []string, header dns.RR_Header) (dns.RR, error){
	dns.TypeNS: func(data []string, header dns.RR_Header) (dns.RR, error) {
		if len(data) != 1 {
			return nil, ErrInvalidSegmentCount
		}
		return &dns.NS{Hdr: header, Ns: data[0]}, nil
	},
	dns.TypeA: func(data []string, header dns.RR_Header) (dns.RR, error) {
		if len(data) != 1 {
			return nil, ErrInvalidSegmentCount
		}
		ip := net.ParseIP(data[0])
		if ip.To4() == nil {
			return nil, errors.New("invalid IPv4 address")
		}
		return &dns.A{Hdr: header, A: ip}, nil
	},
	dns.TypeAAAA: func(data []string, header dns.RR_Header) (dns.RR, error) {
		if len(data) != 1 {
			return nil, ErrInvalidSegmentCount
		}
		ip := net.ParseIP(data[0])
		if ip.To16() == nil {
			return nil, errors.New("invalid IPv6 address")
		}
		return &dns.AAAA{Hdr: header, AAAA: ip}, nil
	},
	dns.TypeTXT: func(data []string, header dns.RR_Header) (dns.RR, error) {
		return &dns.TXT{Hdr: header, Txt: data}, nil
	},
	dns.TypePTR: func(data []string, header dns.RR_Header) (dns.RR, error) {
		if len(data) != 1 {
			return nil, ErrInvalidSegmentCount
		}
		return &dns.PTR{Hdr: header, Ptr: data[0]}, nil
	},
	dns.TypeCNAME: func(data []string, header dns.RR_Header) (dns.RR, error) {
		if len(data) != 1 {
			return nil, ErrInvalidSegmentCount
		}
		return &dns.CNAME{Hdr: header, Target: data[0]}, nil
	},
	dns.TypeMX: func(data []string, header dns.RR_Header) (dns.RR, error) {
		preference, err := strconv.ParseUint(data[0], 10, 16)
		if err != nil {
			return nil, err
		}
		return &dns.MX{
			Hdr:        header,
			Preference: uint16(preference),
			Mx:         data[1],
		}, nil
	},
	dns.TypeSRV: func(data []string, header dns.RR_Header) (dns.RR, error) {
		if len(data) != 4 {
			return nil, ErrInvalidSegmentCount
		}
		priority, err := strconv.ParseUint(data[0], 10, 16)
		if err != nil {
			return nil, err
		}
		weight, err := strconv.ParseUint(data[1], 10, 16)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(data[2], 10, 16)
		if err != nil {
			return nil, err
		}
		return &dns.SRV{
			Hdr:      header,
			Priority: uint16(priority),
			Weight:   uint16(weight),
			Port:     uint16(port),
			Target:   data[3],
		}, nil
	},
}
