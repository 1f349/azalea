package database

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRecord_ZoneFileLine(t *testing.T) {
	tests := []struct {
		record Record
		target string
	}{
		{Record{Name: "@", Type: "A", Value: "10.0.0.1"}, "example.com.\t300\tIN\tA\t10.0.0.1"},
		{Record{Name: "@", Type: "AAAA", Value: "fd01::1"}, "example.com.\t300\tIN\tAAAA\tfd01::1"},
		{Record{Name: "ns1", Type: "A", Value: "10.0.1.0"}, "ns1.example.com.\t300\tIN\tA\t10.0.1.0"},
		{Record{Name: "ns1", Type: "AAAA", Value: "fd01::1:0"}, "ns1.example.com.\t300\tIN\tAAAA\tfd01::1:0"},
	}
	for _, i := range tests {
		rr, err := i.record.ConvertRecord("example.com.")
		assert.NoError(t, err)
		assert.Equal(t, i.target, rr.RR(300).String())
	}
}
