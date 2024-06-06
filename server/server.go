package server

import (
	"github.com/1f349/azalea/database"
	"github.com/1f349/azalea/logger"
	"github.com/256dpi/newdns"
	"github.com/miekg/dns"
	"sync"
)

type DnsServer struct {
	Addr  string
	conf  Conf
	srv   *newdns.Server
	mu    *sync.RWMutex
	zones map[string]*Zone
}

func (d *DnsServer) ZoneHandler(name string) (*newdns.Zone, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	zone := d.zones[name]
	return zone.zone, nil
}

func (d *DnsServer) Run() {
	go func() {
		err := d.srv.Run(d.conf.Listen)
		if err != nil {
			logger.Logger.Error("Failed to start server", "err", err)
		}
	}()
}

func (d *DnsServer) Close() {
	d.srv.Close()
}

func NewDnsServer(conf Conf, db *database.Queries) *DnsServer {
	d := &DnsServer{
		Addr:  conf.Listen,
		conf:  conf,
		mu:    new(sync.RWMutex),
		zones: make(map[string]*Zone, len(conf.Zones)),
	}

	for _, i := range conf.Zones {
		d.zones[i] = NewZone(d, db, conf, i)
	}

	// create server
	d.srv = newdns.NewServer(newdns.Config{
		Zones:   conf.Zones,
		Handler: d.ZoneHandler,
		Logger: func(e newdns.Event, msg *dns.Msg, err error, reason string) {
			if err != nil {
				logger.Logger.Error("zone handler error", "event", e, "err", err, "reason", reason)
			}
		},
	})

	return d
}
