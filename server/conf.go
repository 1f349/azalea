package server

import "net"

type Conf struct {
	Listen string   `json:"listen"`
	Ns     []string `json:"ns"`
	NsTtl  uint32   `json:"ns_ttl"`
	Extra  []Extra  `json:"extra"`
}

type Extra struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value net.IP `json:"value"`
	Ttl   uint32 `json:"ttl"`
}
