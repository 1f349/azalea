package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/1f349/azalea/database"
	"github.com/1f349/azalea/models"
	"github.com/1f349/mjwt/auth"
	"github.com/1f349/mjwt/claims"
	"github.com/golang-jwt/jwt/v4"
	"github.com/julienschmidt/httprouter"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"net"
	"net/http"
	"testing"
	"time"
)

type fakeRecordQueries struct {
}

func (f *fakeRecordQueries) AddZoneRecord(ctx context.Context, params database.AddZoneRecordParams) (int64, error) {
	if params.Zone == 1 && params.Name == "ns1" && params.Type == "A" {
		return 5, nil
	}
	panic("not implemented")
}

func (f *fakeRecordQueries) GetZone(ctx context.Context, zone string) (database.Zone, error) {
	if zone == "example.com." {
		return database.Zone{
			ID:   1,
			Name: "example.com.",
		}, nil
	}
	panic("not implemented")
}

func (f *fakeRecordQueries) GetZoneRecordById(ctx context.Context, params database.GetZoneRecordByIdParams) (database.Record, error) {
	if params.Zone == 1 {
		switch params.ID {
		case 1:
			return database.Record{
				ID:     1,
				Zone:   1,
				Name:   "example.com.",
				Type:   "A",
				Locked: true,
				Value:  "10.0.31.1",
			}, nil
		case 2:
			return database.Record{
				ID:    1,
				Zone:  1,
				Name:  "example.com.",
				Type:  "A",
				Value: "10.0.0.1",
			}, nil
		case 3:
			return database.Record{}, sql.ErrNoRows
		}
	}
	panic("not implemented")
}

func (f *fakeRecordQueries) PutZoneRecordById(ctx context.Context, params database.PutZoneRecordByIdParams) error {
	return nil
}

func (f *fakeRecordQueries) DeleteZoneRecordById(ctx context.Context, params database.DeleteZoneRecordByIdParams) error {
	return nil
}

func TestAddRecordEndpoints(t *testing.T) {
	r := httprouter.New()
	signer := genSigner(t)
	AddRecordEndpoints(r, &fakeRecordQueries{}, &fakeResolver{}, signer)

	makeToken := func() string {
		ps := claims.NewPermStorage()
		ps.Set("azalea:domains")
		ps.Set("domain:owns=example.com")
		return mustGen(signer, "1234", "1234", jwt.ClaimStrings{"example.com"}, 15*time.Minute, &auth.AccessTokenClaims{Perms: ps})
	}
	_ = makeToken

	// tests
	t.Run("POST domains :domain records", func(t *testing.T) {
		makeReq := baseMakeReq(http.MethodPost, "/domains/example.com/records")
		req := makeReq("")
		doTestRequest(t, "no auth", req, r, http.StatusForbidden, "Missing bearer token")
		req = baseMakeReq(http.MethodGet, "/domains/example.org/records")("")
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "invalid domain", req, r, http.StatusNotFound, "Invalid domain")
		req = makeReq("{")
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "invalid json", req, r, http.StatusBadRequest, "Invalid JSON")
		req = makeReq(`{"name":"ns1","type":1,"value":"10.23.41.5"}`)
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "ok", req, r, http.StatusCreated, `{"id":5}`)
	})
	t.Run("GET domains :domain records", func(t *testing.T) {
		makeReq := baseMakeReq(http.MethodGet, "/domains/example.com/records")
		req := makeReq("")
		doTestRequest(t, "no auth", req, r, http.StatusForbidden, "Missing bearer token")
		req = baseMakeReq(http.MethodGet, "/domains/example.org/records")("")
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "invalid domain", req, r, http.StatusNotFound, "Invalid domain")
		req = makeReq("")
		req.Header.Set("Authorization", "Bearer "+makeToken())
		encodeRR, err := json.Marshal([]*models.Record{
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
				Name: "example.com.",
				Type: dns.TypeNS,
				Value: &models.NS{
					Ns: "ns1.example.com.",
				},
			},
			{
				Name: "example.com.",
				Type: dns.TypeA,
				Value: &models.A{
					IP: net.IPv4(10, 0, 0, 1),
				},
			},
			{
				Name: "ns1.example.com.",
				Type: dns.TypeA,
				Value: &models.A{
					IP: net.IPv4(10, 0, 26, 5),
				},
			},
		})
		assert.NoError(t, err)
		doTestRequest(t, "ok", req, r, http.StatusOK, string(encodeRR))
	})
	t.Run("GET domains :domain records :record", func(t *testing.T) {
		makeReq := baseMakeReq(http.MethodGet, "/domains/example.com/records/1")
		req := makeReq("")
		doTestRequest(t, "no auth", req, r, http.StatusForbidden, "Missing bearer token")
		req = baseMakeReq(http.MethodGet, "/domains/example.org/records/1")("")
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "invalid domain", req, r, http.StatusNotFound, "Invalid domain")
		req = makeReq("")
		req.Header.Set("Authorization", "Bearer "+makeToken())
		encodeRR, err := json.Marshal(&models.Record{
			Name:  "example.com.",
			Type:  dns.TypeA,
			Value: &models.A{IP: net.IPv4(10, 0, 31, 1)},
		})
		assert.NoError(t, err)
		doTestRequest(t, "ok", req, r, http.StatusOK, string(encodeRR))
	})
	t.Run("PUT domains :domain records :record", func(t *testing.T) {
		makeReq := baseMakeReq(http.MethodPut, "/domains/example.com/records/2")
		req := makeReq("")
		doTestRequest(t, "no auth", req, r, http.StatusForbidden, "Missing bearer token")
		req = baseMakeReq(http.MethodPut, "/domains/example.org/records/2")("")
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "invalid domain", req, r, http.StatusNotFound, "Invalid domain")
		req = makeReq("{")
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "invalid json", req, r, http.StatusBadRequest, "Invalid JSON")
		req = baseMakeReq(http.MethodPut, "/domains/example.com/records/e3")("{}")
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "invalid record id", req, r, http.StatusBadRequest, "Invalid record ID")
		req = baseMakeReq(http.MethodPut, "/domains/example.com/records/3")("{}")
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "unknown record id", req, r, http.StatusBadRequest, "Invalid record ID")
		req = makeReq(`{"value":"example.org"}`)
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "invalid record value", req, r, http.StatusBadRequest, "Invalid record: ParseAddr(\"example.org\"): unexpected character (at \"example.org\")")
		req = baseMakeReq(http.MethodPut, "/domains/example.com/records/1")(`{"value":"10.0.26.5"}`)
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "record locked", req, r, http.StatusConflict, "Record locked")
		req = makeReq(`{"value":"10.0.26.5"}`)
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "ok", req, r, http.StatusOK, "")
	})
	t.Run("DELETE domains :domain records :record", func(t *testing.T) {
		makeReq := baseMakeReq(http.MethodDelete, "/domains/example.com/records/2")
		req := makeReq("")
		doTestRequest(t, "no auth", req, r, http.StatusForbidden, "Missing bearer token")
		req = baseMakeReq(http.MethodDelete, "/domains/example.org/records/2")("")
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "invalid domain", req, r, http.StatusNotFound, "Invalid domain")
		req = baseMakeReq(http.MethodDelete, "/domains/example.com/records/1")("")
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "record locked", req, r, http.StatusConflict, "Record locked")
		req = makeReq("")
		req.Header.Set("Authorization", "Bearer "+makeToken())
		doTestRequest(t, "ok", req, r, http.StatusOK, "")
	})
}
