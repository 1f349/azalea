package server

import (
	"github.com/1f349/azalea/conf"
	"github.com/1f349/azalea/logger"
	"github.com/1f349/azalea/resolver"
	"github.com/miekg/dns"
	"github.com/rcrowley/go-metrics"
	"sync"
	"time"
)

type DnsServer struct {
	Addr      string
	conf      conf.Conf
	mu        *sync.RWMutex
	resolver  *resolver.Resolver
	closeFunc func()
}

func (d *DnsServer) Run() {
	tcpResponseTimer := metrics.NewTimer()
	metrics.Register("request.handler.tcp.response_time", tcpResponseTimer)
	tcpRequestCounter := metrics.NewCounter()
	metrics.Register("request.handler.tcp.requests", tcpRequestCounter)

	udpResponseTimer := metrics.NewTimer()
	metrics.Register("request.handler.udp.response_time", udpResponseTimer)
	udpRequestCounter := metrics.NewCounter()
	metrics.Register("request.handler.udp.requests", udpRequestCounter)

	tcpDnsHandler := &Handler{
		resolver:       d.resolver,
		requestCounter: tcpRequestCounter,
		responseTimer:  tcpResponseTimer,
	}
	udpDnsHandler := &Handler{
		resolver:       d.resolver,
		requestCounter: udpRequestCounter,
		responseTimer:  udpResponseTimer,
	}

	udpHandler := dns.NewServeMux()
	tcpHandler := dns.NewServeMux()

	tcpHandler.HandleFunc(".", tcpDnsHandler.Handle)
	udpHandler.HandleFunc(".", udpDnsHandler.Handle)

	tcpServer := &dns.Server{
		Addr:         d.conf.Listen,
		Net:          "tcp",
		Handler:      tcpHandler,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	}

	udpServer := &dns.Server{
		Addr:         d.conf.Listen,
		Net:          "udp",
		Handler:      udpHandler,
		UDPSize:      65535,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	}

	start := func(server *dns.Server) {
		err := server.ListenAndServe()
		if err != nil {
			logger.Logger.Error("Failed to start server", "err", err)
		}
	}

	go start(tcpServer)
	go start(udpServer)

	d.closeFunc = func() {
		_ = tcpServer.Shutdown()
		_ = udpServer.Shutdown()
	}
}

func (d *DnsServer) Close() {
	if d.closeFunc != nil {
		d.closeFunc()
	}
}

func NewDnsServer(conf conf.Conf, res *resolver.Resolver) *DnsServer {
	return &DnsServer{
		Addr:     conf.Listen,
		conf:     conf,
		mu:       new(sync.RWMutex),
		resolver: res,
	}
}
