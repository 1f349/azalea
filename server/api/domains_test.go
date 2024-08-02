package api

import (
	"context"
	"encoding/json"
	"github.com/1f349/azalea/database"
	"github.com/1f349/azalea/models"
	"github.com/1f349/mjwt/auth"
	"github.com/golang-jwt/jwt/v4"
	"github.com/julienschmidt/httprouter"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeDomainQueries struct{}

func (f *fakeDomainQueries) AddZone(ctx context.Context, zone string) (int64, error) {
	if zone != "example.com." {
		panic("wrong zone: " + zone)
	}
	return 1, nil
}

func (f *fakeDomainQueries) GetOwnedZones(ctx context.Context, zones []string) ([]database.Zone, error) {
	return []database.Zone{{ID: 1, Name: "example.com."}}, nil
}

func (f *fakeDomainQueries) GetZone(ctx context.Context, zone string) (database.Zone, error) {
	if zone == "example.com." {
		return database.Zone{
			ID:   1,
			Name: "example.com.",
		}, nil
	}
	panic("not implemented")
}

type fakeResolver struct{}

func (f *fakeResolver) GetZoneRecords(ctx context.Context, zone string) ([]*models.Record, error) {
	if zone == "example.com." {
		return []*models.Record{
			{
				Name: "example.com.",
				Type: dns.TypeSOA,
				Value: &models.SOA{
					Ns:      "ns1.example.com.",
					Mbox:    "postmaster.example.com.",
					Serial:  1,
					Refresh: 300,
					Retry:   300,
					Expire:  300,
					Minttl:  300,
				},
			},
			{
				Name:  "example.com.",
				Type:  dns.TypeNS,
				Value: &models.NS{Ns: "ns1.example.com."},
			},
			{
				Name:  "example.com.",
				Type:  dns.TypeA,
				Value: &models.A{IP: net.IPv4(10, 0, 0, 1)},
			},
			{
				Name:  "ns1.example.com.",
				Type:  dns.TypeA,
				Value: &models.A{IP: net.IPv4(10, 0, 26, 5)},
			},
		}, nil
	}
	panic("not implemented")
}

func doTestRequest(t *testing.T, name string, req *http.Request, r *httprouter.Router, code int, output string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Helper()
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		res := rec.Result()
		assert.Equal(t, code, res.StatusCode)
		var a string
		switch {
		case output == "":
			a = ""
		case output[0] == 0:
			a = output[1:]
		case output[0] == '[' || output[0] == '{':
			a = output
		default:
			b, _ := json.Marshal(map[string]string{"error": output})
			a = string(b)
		}
		if a != "" {
			a += "\n"
		}
		assert.Equal(t, a, mustReadAll(res.Body))
	})
}

func baseMakeReq(method, url string) func(body string) *http.Request {
	return func(body string) *http.Request {
		var b io.Reader
		if body != "" {
			b = strings.NewReader(body)
		}
		return httptest.NewRequest(method, url, b)
	}
}

func TestAddDomainEndpoints(t *testing.T) {
	r := httprouter.New()
	signer := genSigner(t)
	AddDomainEndpoints(r, &fakeDomainQueries{}, &fakeResolver{}, signer.KeyStore())

	makeToken := func() string {
		ps := auth.NewPermStorage()
		ps.Set("azalea:domains")
		ps.Set("domain:owns=example.com")
		return mustGen(signer, "1234", "1234", jwt.ClaimStrings{"example.com"}, 15*time.Minute, &auth.AccessTokenClaims{Perms: ps})
	}

	// tests
	t.Run("POST domains", func(t *testing.T) {
		makeReq := baseMakeReq(http.MethodPost, "/domains")
		req := makeReq("")
		doTestRequest(t, "no auth", req, r, http.StatusForbidden, "Missing bearer token")
		req = makeReq("{")
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "bad request", req, r, http.StatusBadRequest, "Bad Request")
		req = makeReq(`{"name":"example.com."}`)
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "ok", req, r, http.StatusOK, `{"id":1,"name":"example.com."}`)
	})
	t.Run("GET domains", func(t *testing.T) {
		makeReq := baseMakeReq(http.MethodGet, "/domains")
		req := makeReq("")
		doTestRequest(t, "no auth", req, r, http.StatusForbidden, "Missing bearer token")
		req = makeReq(`{"name":"example.com.","ns":"ns1.example.org.","mbox":"postmaster.example.org.","serial":1,"refresh":1,"retry":1,"expire":1,"ttl":1}`)
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "ok", req, r, http.StatusOK, `[{"id":1,"name":"example.com."}]`)
	})
	t.Run("GET domains example.com", func(t *testing.T) {
		makeReq := baseMakeReq(http.MethodGet, "/domains/example.com")
		req := makeReq("")
		doTestRequest(t, "no auth", req, r, http.StatusForbidden, "Missing bearer token")
		req = makeReq(`{"name":"example.com.","ns":"ns1.example.org.","mbox":"postmaster.example.org.","serial":1,"refresh":1,"retry":1,"expire":1,"ttl":1}`)
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "ok", req, r, http.StatusOK, `{"id":1,"name":"example.com."}`)
	})
	t.Run("GET domains example.com zone-file", func(t *testing.T) {
		makeReq := baseMakeReq(http.MethodGet, "/domains/example.com/zone-file")
		req := makeReq("")
		doTestRequest(t, "no auth", req, r, http.StatusForbidden, "Missing bearer token")
		req = makeReq(`{"name":"example.com.","ns":"ns1.example.org.","mbox":"postmaster.example.org.","serial":1,"refresh":1,"retry":1,"expire":1,"ttl":1}`)
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "ok", req, r, http.StatusOK, "\000"+`; Zone file for example.com.
@	300	IN	SOA	ns1.example.com. postmaster.example.com. 1 300 300 300 300
@	300	IN	NS	ns1.example.com.
@	300	IN	A	10.0.0.1
ns1	300	IN	A	10.0.26.5`)
	})
}
