package converters

import (
	"errors"
	"fmt"
	"github.com/1f349/azalea/models"
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

var Converters = map[uint16]func(data []string) (models.RecordValue, error){
	dns.TypeNS: func(data []string) (models.RecordValue, error) {
		if len(data) != 1 {
			return nil, ErrInvalidSegmentCount
		}
		return &models.NS{Ns: data[0]}, nil
	},
	dns.TypeA: func(data []string) (models.RecordValue, error) {
		if len(data) != 1 {
			return nil, ErrInvalidSegmentCount
		}
		ip := net.ParseIP(data[0])
		if ip.To4() == nil {
			return nil, errors.New("invalid IPv4 address")
		}
		return &models.A{IP: ip}, nil
	},
	dns.TypeAAAA: func(data []string) (models.RecordValue, error) {
		if len(data) != 1 {
			return nil, ErrInvalidSegmentCount
		}
		ip := net.ParseIP(data[0])
		if ip.To16() == nil {
			return nil, errors.New("invalid IPv6 address")
		}
		return &models.AAAA{IP: ip}, nil
	},
	dns.TypeTXT: func(data []string) (models.RecordValue, error) {
		return &models.TXT{Value: data[0]}, nil
	},
	dns.TypeCNAME: func(data []string) (models.RecordValue, error) {
		if len(data) != 1 {
			return nil, ErrInvalidSegmentCount
		}
		return &models.CNAME{Target: data[0]}, nil
	},
	dns.TypeMX: func(data []string) (models.RecordValue, error) {
		preference, err := strconv.ParseUint(data[0], 10, 16)
		if err != nil {
			return nil, err
		}
		return &models.MX{
			Preference: uint16(preference),
			Mx:         data[1],
		}, nil
	},
	dns.TypeSRV: func(data []string) (models.RecordValue, error) {
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
		return &models.SRV{
			Priority: uint16(priority),
			Weight:   uint16(weight),
			Port:     uint16(port),
			Target:   data[3],
		}, nil
	},
}
