// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0

package database

import (
	"net"
)

type ARecord struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Value net.IP `json:"value"`
	Ttl   int64  `json:"ttl"`
}

type AaaaRecord struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Value net.IP `json:"value"`
	Ttl   int64  `json:"ttl"`
}

type CnameRecord struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"`
	Ttl   int64  `json:"ttl"`
}

type MxRecord struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Priority int64  `json:"priority"`
	Value    string `json:"value"`
	Ttl      int64  `json:"ttl"`
}

type SoaRecord struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Ns      string `json:"ns"`
	Mbox    string `json:"mbox"`
	Serial  int64  `json:"serial"`
	Refresh int64  `json:"refresh"`
	Retry   int64  `json:"retry"`
	Expire  int64  `json:"expire"`
	Ttl     int64  `json:"ttl"`
}

type SrvRecord struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Target   string `json:"target"`
	Priority int64  `json:"priority"`
	Weight   int64  `json:"weight"`
	Port     int64  `json:"port"`
	Ttl      int64  `json:"ttl"`
}

type TxtRecord struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Priority int64  `json:"priority"`
	Value    string `json:"value"`
	Ttl      int64  `json:"ttl"`
}