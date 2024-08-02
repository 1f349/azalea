package api

import (
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/auth"
	"github.com/golang-jwt/jwt/v4"
	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func genSigner(t *testing.T) *mjwt.Issuer {
	a, err := mjwt.NewIssuer("test", "test", jwt.SigningMethodRS512)
	assert.NoError(t, err)
	return a
}

func mustGen(signer *mjwt.Issuer, sub, id string, aud jwt.ClaimStrings, dur time.Duration, claims mjwt.Claims) string {
	key, err := signer.GenerateJwt(sub, id, aud, dur, claims)
	if err != nil {
		panic(err)
	}
	return key
}

func mustReadAll(r io.Reader) string {
	all, err := io.ReadAll(r)
	if err != nil {
		panic(err)
	}
	return string(all)
}

func doReq(t *testing.T, signer *mjwt.Issuer, key string, testStatus int, testBody string) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://example.com", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	checkAuth(signer.KeyStore(), func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		assert.Equal(t, "Bearer "+key, req.Header.Get("Authorization"))
		assert.Equal(t, "access-token", b.ClaimType)
		assert.Equal(t, jwt.ClaimStrings{"example.com"}, b.Audience)
		rw.Write([]byte("OK\n"))
	})(rec, req, httprouter.Params{})
	res := rec.Result()
	assert.Equal(t, testStatus, res.StatusCode)
	assert.Equal(t, testBody, mustReadAll(res.Body))
}

func doReqWithPerm(t *testing.T, signer *mjwt.Issuer, key, perm string, testStatus int, testBody string) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://example.com", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	checkAuthWithPerm(signer.KeyStore(), perm, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		assert.Equal(t, "Bearer "+key, req.Header.Get("Authorization"))
		assert.Equal(t, "access-token", b.ClaimType)
		assert.Equal(t, jwt.ClaimStrings{"example.com"}, b.Audience)
		rw.Write([]byte("OK\n"))
	})(rec, req, httprouter.Params{})
	res := rec.Result()
	assert.Equal(t, testStatus, res.StatusCode)
	assert.Equal(t, testBody, mustReadAll(res.Body))
}

func TestCheckAuth(t *testing.T) {
	signer := genSigner(t)
	t.Run("valid token", func(t *testing.T) {
		key := mustGen(signer, "1234", "1234", jwt.ClaimStrings{"example.com"}, 15*time.Minute, &auth.AccessTokenClaims{})
		doReq(t, signer, key, http.StatusOK, "OK\n")
	})
	t.Run("invalid token", func(t *testing.T) {
		signer2 := genSigner(t)
		key := mustGen(signer2, "1234", "1234", jwt.ClaimStrings{"example.com"}, 15*time.Minute, &auth.AccessTokenClaims{})
		doReq(t, signer, key, http.StatusForbidden, "{\"error\":\"Invalid token\"}\n")
	})
}

func TestCheckAuthWithPerm(t *testing.T) {
	signer := genSigner(t)
	t.Run("valid token", func(t *testing.T) {
		ps := auth.NewPermStorage()
		ps.Set("test.perm")
		key := mustGen(signer, "1234", "1234", jwt.ClaimStrings{"example.com"}, 15*time.Minute, &auth.AccessTokenClaims{
			Perms: ps,
		})
		doReqWithPerm(t, signer, key, "test.perm", http.StatusOK, "OK\n")
	})
	t.Run("invalid token", func(t *testing.T) {
		ps := auth.NewPermStorage()
		ps.Set("test.perm")
		signer2 := genSigner(t)
		key := mustGen(signer2, "1234", "1234", jwt.ClaimStrings{"example.com"}, 15*time.Minute, &auth.AccessTokenClaims{
			Perms: ps,
		})
		doReqWithPerm(t, signer, key, "test.perm", http.StatusForbidden, "{\"error\":\"Invalid token\"}\n")
	})
	t.Run("invalid perm", func(t *testing.T) {
		ps := auth.NewPermStorage()
		ps.Set("test2.perm")
		key := mustGen(signer, "1234", "1234", jwt.ClaimStrings{"example.com"}, 15*time.Minute, &auth.AccessTokenClaims{
			Perms: ps,
		})
		doReqWithPerm(t, signer, key, "test.perm", http.StatusForbidden, "{\"error\":\"No permission\"}\n")
	})
	t.Run("invalid perm and token", func(t *testing.T) {
		ps := auth.NewPermStorage()
		ps.Set("test2.perm")
		signer2 := genSigner(t)
		key := mustGen(signer2, "1234", "1234", jwt.ClaimStrings{"example.com"}, 15*time.Minute, &auth.AccessTokenClaims{
			Perms: ps,
		})
		doReqWithPerm(t, signer, key, "test.perm", http.StatusForbidden, "{\"error\":\"Invalid token\"}\n")
	})
}
