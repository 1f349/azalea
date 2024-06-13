package server

type Conf struct {
	Listen string   `json:"listen"`
	Ns     []string `json:"ns"`
	Ttl    uint32   `json:"ttl"`
}
