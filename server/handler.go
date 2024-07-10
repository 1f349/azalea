package server

import (
	"context"
	"github.com/1f349/azalea/logger"
	"github.com/1f349/azalea/resolver"
	"github.com/miekg/dns"
	"github.com/rcrowley/go-metrics"
)

type Handler struct {
	resolver *resolver.Resolver

	responseTimer  metrics.Timer
	requestCounter metrics.Counter
}

func (h *Handler) Handle(response dns.ResponseWriter, req *dns.Msg) {
	h.requestCounter.Inc(1)
	h.responseTimer.Time(func() {
		if len(req.Question) >= 0 {
			logger.Logger.Debug("Handling incoming query", "domain", req.Question[0].Name, "type", dns.TypeToString[req.Question[0].Qtype])
		} else {
			logger.Logger.Debug("Handling incoming query with no question")
		}

		var msg *dns.Msg
		msg = h.resolver.Lookup(context.Background(), req, response.RemoteAddr())
		if msg != nil {
			err := response.WriteMsg(msg)
			if err != nil {
				logger.Logger.Error("Error writing message", "err", err)
			}
		}

		logger.Logger.Debug("Sent response", "addr", response.RemoteAddr())
	})
}
