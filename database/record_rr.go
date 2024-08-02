package database

import (
	"fmt"
	"github.com/1f349/azalea/converters"
	"github.com/1f349/azalea/models"
	"github.com/1f349/azalea/utils"
	"github.com/miekg/dns"
	"strings"
)

func (r Record) ConvertRecord(zone string) (*models.Record, error) {
	name := utils.ResolveRecordName(r.Name, zone)
	record := &models.Record{
		Name: name,
		Type: dns.StringToType[r.Type],
		Ttl:  r.Ttl,
	}
	if record.Type == dns.TypeNone {
		return nil, converters.ErrInvalidRecord{Name: name, Value: r.Value, AType: r.Type, Reason: fmt.Errorf("invalid type %s", r.Type)}
	}

	// get data segments
	data := strings.Split(r.Value, "\t")
	if len(data) == 0 {
		return nil, converters.ErrInvalidRecord{Name: name, Value: r.Value, AType: r.Type, Reason: converters.ErrInvalidSegmentCount}
	}
	convert, found := converters.Converters[record.Type]
	if !found {
		return nil, converters.ErrInvalidRecord{Name: name, Value: r.Value, AType: r.Type, Reason: fmt.Errorf("unsupported record type %s", r.Type)}
	}
	recordValue, err := convert(data)
	if err != nil {
		return nil, converters.ErrInvalidRecord{Name: name, Value: r.Value, AType: r.Type, Reason: err}
	}
	record.Value = recordValue
	return record, nil
}

func (r Record) IsLocationResolving() bool {
	return r.Type == "LOC_RES"
}

func (r LookupRecordsForTypeRow) ConvertRecord() (*models.Record, error) {
	return Record{
		ID:     r.ID,
		Zone:   r.Zone,
		Name:   r.Name,
		Type:   r.Type,
		Locked: r.Locked,
		Ttl:    r.Ttl,
		Value:  r.Value,
	}.ConvertRecord(r.ZoneName)
}

func (r LookupRecordsForTypeRow) IsLocationResolving() bool {
	return r.Type == "LOC_RES"
}
