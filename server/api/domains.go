package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/1f349/azalea/database"
	"github.com/1f349/azalea/models"
	"github.com/1f349/mjwt"
	"github.com/julienschmidt/httprouter"
	"github.com/miekg/dns"
	"net/http"
	"strings"
)

type domainQueries interface {
	AddZone(ctx context.Context, zone string) (int64, error)
	GetOwnedZones(ctx context.Context, zones []string) ([]database.Zone, error)
	GetZone(ctx context.Context, zone string) (database.Zone, error)
}

type domainResolver interface {
	GetZoneRecords(ctx context.Context, zone string) ([]*models.Record, error)
}

func AddDomainEndpoints(r *httprouter.Router, db domainQueries, res domainResolver, verify mjwt.Verifier) {
	// Endpoints for domains
	r.POST("/domains", checkAuthWithPerm(verify, "azalea:domains", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		var a struct {
			Name string `json:"name"`
		}
		dec := json.NewDecoder(req.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&a)
		if err != nil {
			apiError(rw, http.StatusBadRequest, "Bad Request")
			return
		}
		if !validateZoneOwnershipClaims(a.Name, b.Claims.Perms) {
			apiError(rw, http.StatusNotFound, "Invalid domain")
			return
		}
		zoneId, err := db.AddZone(req.Context(), a.Name)
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Internal database error")
			return
		}
		rw.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(rw).Encode(struct {
			Id   int64  `json:"id"`
			Name string `json:"name"`
		}{
			Id:   zoneId,
			Name: a.Name,
		})
	}))
	r.GET("/domains", checkAuthWithPerm(verify, "azalea:domains", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		zones, err := db.GetOwnedZones(req.Context(), getZoneOwnershipClaims(b.Claims.Perms))
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Internal database error")
			return
		}
		_ = json.NewEncoder(rw).Encode(zones)
	}))
	r.POST("/domains/:domain/import", checkAuthWithPerm(verify, "azalea:domains", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		// TODO: implement this
		apiError(rw, http.StatusNotImplemented, "Not Implemented")
	}))
	r.GET("/domains/:domain", checkAuthWithPerm(verify, "azalea:domains", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		domain := dns.Fqdn(params.ByName("domain"))
		if !validateZoneOwnershipClaims(domain, b.Claims.Perms) {
			apiError(rw, http.StatusNotFound, "Invalid domain")
			return
		}
		zone, err := db.GetZone(req.Context(), domain)
		if errors.Is(err, sql.ErrNoRows) {
			apiError(rw, http.StatusNotFound, "Invalid domain")
			return
		}
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Internal database error")
			return
		}
		_ = json.NewEncoder(rw).Encode(zone)
	}))
	r.DELETE("/domains/:domain", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		// TODO: implement this
		apiError(rw, http.StatusNotImplemented, "Not Implemented")
	})

	// Endpoint for getting a domain zone file
	r.GET("/domains/:domain/zone-file", checkAuthWithPerm(verify, "azalea:domains", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		zone := dns.Fqdn(params.ByName("domain"))
		if !validateZoneOwnershipClaims(zone, b.Claims.Perms) {
			apiError(rw, http.StatusNotFound, "Invalid domain")
			return
		}
		records, err := res.GetZoneRecords(req.Context(), zone)
		if errors.Is(err, sql.ErrNoRows) {
			apiError(rw, http.StatusNotFound, "Invalid domain")
			return
		}
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Internal database error")
			return
		}

		// comment with zone name
		_, err = fmt.Fprintf(rw, "; Zone file for %s\n", zone)
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Zone file generation error")
			return
		}

		for _, i := range records {
			line := i.RR(300).String()

			if strings.Count(line, "\t") > 2 {
				prefix, suffix, _ := strings.Cut(line, "\t")
				if prefix == zone {
					prefix = "@"
				} else {
					prefix, _ = strings.CutSuffix(prefix, "."+zone)
				}
				line = prefix + "\t" + suffix
			}

			_, err = fmt.Fprintln(rw, line)
			if err != nil {
				apiError(rw, http.StatusInternalServerError, "Zone file generation error")
				return
			}
		}
	}))
}
