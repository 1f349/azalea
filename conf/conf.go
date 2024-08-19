package conf

type Conf struct {
	Listen      ListenConf `yaml:"listen"`
	DB          string     `yaml:"db"`
	Master      bool       `yaml:"master"`
	GeoIP       string     `yaml:"geoip"`
	MetricsAuth string     `yaml:"metricsAuth"`
	Soa         SoaConf    `yaml:"soa"`
}

type ListenConf struct {
	Dns string `yaml:"dns"`
	Api string `yaml:"api"`
}

type SoaConf struct {
	Ns      []string `yaml:"ns"`
	Mbox    string   `yaml:"mbox"`
	Refresh uint32   `yaml:"refresh"`
	Retry   uint32   `yaml:"retry"`
	Expire  uint32   `yaml:"expire"`
	Ttl     uint32   `yaml:"ttl"`
}
