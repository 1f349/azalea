package conf

type Conf struct {
	Listen    string  `yaml:"listen"`
	ApiListen string  `yaml:"apiListen"`
	DB        string  `yaml:"db"`
	Master    bool    `yaml:"master"`
	GeoIP     string  `yaml:"geoip"`
	Soa       SoaConf `yaml:"soa"`
}

type SoaConf struct {
	Ns      []string `yaml:"ns"`
	Mbox    string   `yaml:"mbox"`
	Refresh uint32   `yaml:"refresh"`
	Retry   uint32   `yaml:"retry"`
	Expire  uint32   `yaml:"expire"`
	Ttl     uint32   `yaml:"ttl"`
}
