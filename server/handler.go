package server

import (
	"github.com/1f349/azalea/logger"
	"github.com/miekg/dns"
	"github.com/rcrowley/go-metrics"
)

type Handler struct {
	resolver *Resolver

	responseTimer  metrics.Timer
	requestCounter metrics.Counter
}

func (h *Handler) Handle(response dns.ResponseWriter, req *dns.Msg) {
	h.requestCounter.Inc(1)
	h.responseTimer.Time(func() {
		logger.Logger.Debug("Handling incoming query for domain " + req.Question[0].Name)

		var msg *dns.Msg
		msg = h.resolver.Lookup(req)
		if msg != nil {
			err := response.WriteMsg(msg)
			if err != nil {
				logger.Logger.Error("Error writing message", "err", err)
			}
		}

		logger.Logger.Debug("Sent response", "addr", response.RemoteAddr())
	})
}
