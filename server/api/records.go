package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/1f349/azalea/database"
	"github.com/1f349/mjwt"
	validateDomain "github.com/chmike/domain"
	"github.com/julienschmidt/httprouter"
	"github.com/miekg/dns"
	"net/http"
	"net/netip"
	"strconv"
)

type recordQueries interface {
	AddZoneRecord(ctx context.Context, params database.AddZoneRecordParams) (int64, error)
	GetZone(ctx context.Context, zone string) (database.Zone, error)
	GetZoneRecordById(ctx context.Context, params database.GetZoneRecordByIdParams) (database.Record, error)
	PutZoneRecordById(ctx context.Context, params database.PutZoneRecordByIdParams) error
	DeleteZoneRecordById(ctx context.Context, params database.DeleteZoneRecordByIdParams) error
}

type recordResolver interface {
	GetZoneRecords(ctx context.Context, zone string) ([]dns.RR, error)
}

type recordValue struct {
	Hdr   *dns.RR_Header
	Value json.RawMessage `json:"value"`
}

func AddRecordEndpoints(r *httprouter.Router, db recordQueries, res recordResolver, verify mjwt.Verifier) {
	// Endpoints for records
	r.POST("/domains/:domain/records", checkAuthWithPerm(verify, "azalea:domains", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		domain := dns.Fqdn(params.ByName("domain"))
		if !validateZoneOwnershipClaims(domain, b.Claims.Perms) {
			apiError(rw, http.StatusNotFound, "Invalid domain")
			return
		}

		// decode json data
		var a recordValue
		dec := json.NewDecoder(req.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&a)
		if err != nil {
			apiError(rw, http.StatusBadRequest, "Invalid JSON")
			return
		}

		err = validateDomain.Check(a.Hdr.Name)
		if err != nil {
			apiError(rw, http.StatusBadRequest, "Invalid record name")
			return
		}

		if _, validType := dns.TypeToString[a.Hdr.Rrtype]; !validType {
			apiError(rw, http.StatusBadRequest, "Invalid record type")
			return
		}

		value, done := parseRecordValue(rw, a)
		if done {
			return
		}

		zone, err := db.GetZone(req.Context(), domain)
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Internal database error")
			return
		}
		recordId, err := db.AddZoneRecord(req.Context(), database.AddZoneRecordParams{
			Zone:   zone.ID,
			Name:   a.Hdr.Name,
			Type:   dns.TypeToString[a.Hdr.Rrtype],
			Locked: false,
			Value:  value,
		})
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Internal database error")
			return
		}
		rw.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(rw).Encode(struct {
			ID int64 `json:"id"`
		}{
			ID: recordId,
		})
	}))
	r.GET("/domains/:domain/records", checkAuthWithPerm(verify, "azalea:domains", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		domain := dns.Fqdn(params.ByName("domain"))
		if !validateZoneOwnershipClaims(domain, b.Claims.Perms) {
			apiError(rw, http.StatusNotFound, "Invalid domain")
			return
		}
		records, err := res.GetZoneRecords(req.Context(), domain)
		if errors.Is(err, sql.ErrNoRows) {
			apiError(rw, http.StatusInternalServerError, "Zone records not found")
			return
		}
		if err != nil {
			http.Error(rw, "Internal server error", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(rw).Encode(records)
	}))

	// Endpoints for interacting with a single record
	r.GET("/domains/:domain/records/:record", checkAuthWithPerm(verify, "azalea:domains", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		domain := dns.Fqdn(params.ByName("domain"))
		record := params.ByName("record")
		if !validateZoneOwnershipClaims(domain, b.Claims.Perms) {
			apiError(rw, http.StatusNotFound, "Invalid domain")
			return
		}
		zone, err := db.GetZone(req.Context(), domain)
		if err != nil {
			apiError(rw, http.StatusNotFound, "Invalid domain")
			return
		}
		recordId, err := strconv.ParseInt(record, 10, 64)
		if err != nil {
			apiError(rw, http.StatusBadRequest, "Invalid record ID")
			return
		}
		zoneRecord, err := db.GetZoneRecordById(req.Context(), database.GetZoneRecordByIdParams{
			Zone: zone.ID,
			ID:   int32(recordId),
		})
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Internal database error")
			return
		}
		rr, err := zoneRecord.RR(domain, 300)
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Failed to generate record")
			return
		}
		_ = json.NewEncoder(rw).Encode(rr)
	}))
	r.PUT("/domains/:domain/records/:record", checkAuthWithPerm(verify, "azalea:domains", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		domain := dns.Fqdn(params.ByName("domain"))
		record := params.ByName("record")
		if !validateZoneOwnershipClaims(domain, b.Claims.Perms) {
			apiError(rw, http.StatusNotFound, "Invalid domain")
			return
		}

		// decode json data
		var a struct {
			Value json.RawMessage `json:"value"`
		}
		dec := json.NewDecoder(req.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&a)
		if err != nil {
			apiError(rw, http.StatusBadRequest, "Invalid JSON")
			return
		}

		zone, err := db.GetZone(req.Context(), domain)
		if err != nil {
			apiError(rw, http.StatusBadRequest, "Invalid domain")
			return
		}
		recordId, err := strconv.ParseInt(record, 10, 64)
		if err != nil {
			apiError(rw, http.StatusBadRequest, "Invalid record ID")
			return
		}
		zoneRecord, err := db.GetZoneRecordById(req.Context(), database.GetZoneRecordByIdParams{
			Zone: zone.ID,
			ID:   int32(recordId),
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				apiError(rw, http.StatusBadRequest, "Invalid record ID")
				return
			}
			apiError(rw, http.StatusInternalServerError, "Internal database error")
			return
		}
		if zoneRecord.Locked {
			apiError(rw, http.StatusConflict, "Record locked")
			return
		}

		value, done := parseRecordValue(rw, recordValue{
			Hdr: &dns.RR_Header{
				Name:   zoneRecord.Name,
				Rrtype: dns.StringToType[zoneRecord.Type],
				Class:  dns.ClassINET,
			},
			Value: a.Value,
		})
		if done {
			return
		}

		err = db.PutZoneRecordById(req.Context(), database.PutZoneRecordByIdParams{
			Value: value,
			Zone:  zone.ID,
			ID:    int32(recordId),
		})
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Internal database error")
			return
		}

		rw.WriteHeader(http.StatusOK)
	}))
	r.DELETE("/domains/:domain/records/:record", checkAuthWithPerm(verify, "azalea:domains", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		domain := dns.Fqdn(params.ByName("domain"))
		record := params.ByName("record")
		if !validateZoneOwnershipClaims(domain, b.Claims.Perms) {
			apiError(rw, http.StatusNotFound, "Invalid domain")
			return
		}

		zone, err := db.GetZone(req.Context(), domain)
		if err != nil {
			apiError(rw, http.StatusBadRequest, "Invalid domain")
			return
		}
		recordId, err := strconv.ParseInt(record, 10, 64)
		if err != nil {
			apiError(rw, http.StatusBadRequest, "Invalid record ID")
			return
		}

		zoneRecord, err := db.GetZoneRecordById(req.Context(), database.GetZoneRecordByIdParams{
			Zone: zone.ID,
			ID:   int32(recordId),
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				apiError(rw, http.StatusBadRequest, "Invalid record ID")
				return
			}
			apiError(rw, http.StatusInternalServerError, "Internal database error")
			return
		}
		if zoneRecord.Locked {
			apiError(rw, http.StatusConflict, "Record locked")
			return
		}

		err = db.DeleteZoneRecordById(req.Context(), database.DeleteZoneRecordByIdParams{
			Zone: zone.ID,
			ID:   int32(recordId),
		})
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Internal database error")
			return
		}

		rw.WriteHeader(http.StatusOK)
	}))
}

func parseRecordValue(rw http.ResponseWriter, a recordValue) (string, bool) {
	var value string
	switch a.Hdr.Rrtype {
	case dns.TypeMX:
		// TODO(melon): implement this
		apiError(rw, http.StatusNotImplemented, "Not Implemented")
		return "", true
	case dns.TypeA, dns.TypeAAAA:
		var ip netip.Addr
		err := json.Unmarshal(a.Value, &ip)
		if err != nil {
			apiError(rw, http.StatusBadRequest, "Invalid IP")
			return "", true
		}
		if ip.Zone() != "" {
			apiError(rw, http.StatusBadRequest, "Zones are not supported")
			return "", true
		}
		// check if parsed address is valid for this record type
		if (a.Hdr.Rrtype == dns.TypeA && ip.Is4()) || (a.Hdr.Rrtype == dns.TypeAAAA && ip.Is6()) {
			value = ip.String()
		}
	case dns.TypeCNAME:
		err := json.Unmarshal(a.Value, &value)
		if err != nil {
			apiError(rw, http.StatusBadRequest, "Invalid CNAME value")
			return "", true
		}
		if _, ok := dns.IsDomainName(value); !ok {
			apiError(rw, http.StatusBadRequest, "Invalid CNAME value")
			return "", true
		}
		value = dns.Fqdn(value)
	case dns.TypeTXT:
		err := json.Unmarshal(a.Value, &value)
		if err != nil {
			apiError(rw, http.StatusBadRequest, "Invalid TXT value")
			return "", true
		}
	case dns.TypeSRV:
		// TODO(melon): implement this
		apiError(rw, http.StatusNotImplemented, "Not Implemented")
		return "", true
	case dns.TypeCAA:
		// TODO(melon): implement this
		apiError(rw, http.StatusNotImplemented, "Not Implemented")
		return "", true
	default:
		apiError(rw, http.StatusBadRequest, "Invalid record type")
		return "", true
	}
	if value == "" {
		apiError(rw, http.StatusBadRequest, "Invalid record value")
		return "", true
	}
	return value, false
}
