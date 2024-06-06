package server

type Conf struct {
	Listen     string   `json:"listen"`
	Hostmaster string   `json:"hostmaster"`
	Ns         []string `json:"ns"`
	Zones      []string `json:"zones"`
}
