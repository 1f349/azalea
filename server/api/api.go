package api

import (
	"encoding/json"
	"github.com/1f349/azalea/database"
	"github.com/1f349/azalea/resolver"
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/claims"
	"github.com/1f349/violet/utils"
	"github.com/julienschmidt/httprouter"
	"github.com/miekg/dns"
	"github.com/rcrowley/go-metrics"
	"net/http"
	"strings"
)

func NewApiServer(db *database.Queries, res *resolver.Resolver, verify mjwt.Verifier) *httprouter.Router {
	r := httprouter.New()

	r.GET("/", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		http.Error(rw, "Azalea API Endpoint", http.StatusOK)
	})
	r.GET("/metrics", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		_ = json.NewEncoder(rw).Encode(metrics.DefaultRegistry.GetAll())
	})

	AddDomainEndpoints(r, db, res, verify)
	AddRecordEndpoints(r, db, res, verify)

	return r
}

// apiError outputs a generic JSON error message
func apiError(rw http.ResponseWriter, code int, m string) {
	rw.WriteHeader(code)
	_ = json.NewEncoder(rw).Encode(map[string]string{
		"error": m,
	})
}

// getZoneOwnershipClaims returns the domains marked as owned from PermStorage,
// they match `domain:owns=<fqdn>` where fqdn will be returned
func getZoneOwnershipClaims(perms *claims.PermStorage) []string {
	a := perms.Search("domain:owns=*")
	for i := range a {
		a[i] = dns.Fqdn(a[i][len("domain:owns="):])
	}
	return a
}

// validateZoneOwnershipClaims validates if the claims contain the
// `domain:owns=<fqdn>` field with the matching top level domain
func validateZoneOwnershipClaims(a string, perms *claims.PermStorage) bool {
	a = strings.TrimRight(a, ".")
	if fqdn, ok := utils.GetTopFqdn(a); ok {
		if perms.Has("domain:owns=" + fqdn) {
			return true
		}
	}
	return false
}
