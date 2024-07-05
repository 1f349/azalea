package utils

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestResolveRecordName(t *testing.T) {
	tests := [][3]string{
		{"@", "example.com.", "example.com."},
		{"", "example.com.", "example.com."},
		{"ns1", "example.com.", "ns1.example.com."},
		{"ns2", "example.com.", "ns2.example.com."},
		{"ns2.example.com.", "example.org.", "ns2.example.com."},
		{"ns3", "", "ns3."},
	}
	for _, i := range tests {
		assert.Equal(t, i[2], ResolveRecordName(i[0], i[1]))
	}
}

func TestSimplifyRecordName(t *testing.T) {
	tests := [][3]string{
		{"example.com.", "example.com.", "@"},
		{"ns1.example.com.", "example.com.", "ns1"},
		{"ns2.example.com.", "example.org.", "ns2.example.com."},
	}
	for _, i := range tests {
		assert.Equal(t, i[2], SimplifyRecordName(i[0], i[1]))
	}
}

func FuzzResolveAndSimplifyRecordName(f *testing.F) {
	f.Fuzz(func(t *testing.T, a string) {
		out := a
		if out == "" {
			out = "@"
		}
		if strings.HasSuffix(out, ".") {
			return
		}
		assert.Equal(t, out, SimplifyRecordName(ResolveRecordName(a, "example.com."), "example.com."))
	})
}

func FuzzSimplifyAndResolveRecordName(f *testing.F) {
	f.Fuzz(func(t *testing.T, a string) {
		out := a
		if !strings.HasSuffix(out, ".") {
			return
		}
		assert.Equal(t, out, ResolveRecordName(SimplifyRecordName(a, "example.com."), "example.com."))
	})
}
