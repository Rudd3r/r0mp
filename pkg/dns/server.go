package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/miekg/dns"
)

type Server struct {
	addr     string
	mappings []domain.DNSMapping
	log      *slog.Logger
	server   *dns.Server
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func NewServer(ctx context.Context, log *slog.Logger, addr string, mappings []domain.DNSMapping) *Server {
	ctx, cancel := context.WithCancel(ctx)
	return &Server{
		addr:     addr,
		mappings: mappings,
		log:      log,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (d *Server) Start() error {
	pc, err := net.ListenPacket("udp", d.addr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}

	d.server = &dns.Server{
		PacketConn: pc,
		Handler:    dns.HandlerFunc(d.handleDNSRequest),
	}

	d.log.Info("DNS server started", "addr", d.addr)

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		if err := d.server.ActivateAndServe(); err != nil && d.ctx.Err() == nil {
			d.log.Error("DNS server error", "error", err)
		}
	}()

	<-d.ctx.Done()
	_ = d.server.Shutdown()
	d.wg.Wait()

	return nil
}

func (d *Server) Stop() {
	d.cancel()
}

func (d *Server) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		d.log.Warn("no questions in DNS request")
		return
	}

	question := req.Question[0]
	domain := strings.TrimSuffix(question.Name, ".")

	d.log.Info("DNS query", "domain", domain, "type", dns.TypeToString[question.Qtype], "class", dns.ClassToString[question.Qclass])

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true

	ip := d.matchDomain(domain)
	if ip == nil {
		msg.SetRcode(req, dns.RcodeNameError)
		_ = w.WriteMsg(msg)
		return
	}

	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		msg.SetRcode(req, dns.RcodeNotImplemented)
		_ = w.WriteMsg(msg)
		return
	}

	isIPv4 := ip.To4() != nil
	if question.Qtype == dns.TypeA && !isIPv4 {
		_ = w.WriteMsg(msg)
		return
	}
	if question.Qtype == dns.TypeAAAA && isIPv4 {
		_ = w.WriteMsg(msg)
		return
	}

	var rr dns.RR
	switch question.Qtype {
	case dns.TypeA:
		rr = &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: ip.To4(),
		}
	case dns.TypeAAAA:
		rr = &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			AAAA: ip.To16(),
		}
	}

	msg.Answer = append(msg.Answer, rr)
	_ = w.WriteMsg(msg)
}

func (d *Server) matchDomain(domain string) net.IP {
	domain = strings.ToLower(domain)

	for _, mapping := range d.mappings {
		pattern := strings.ToLower(mapping.Pattern)

		if pattern == domain {
			return mapping.IP
		}
	}

	for _, mapping := range d.mappings {
		pattern := strings.ToLower(mapping.Pattern)

		if strings.Contains(pattern, "*") {
			if d.matchWildcard(pattern, domain) {
				return mapping.IP
			}
		}
	}

	return nil
}

func (d *Server) matchWildcard(pattern, domain string) bool {
	if pattern == "*" {
		return true
	}

	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	suffix := pattern[1:]
	if !strings.HasSuffix(domain, suffix) {
		return false
	}

	prefix := domain[:len(domain)-len(suffix)]
	return !strings.Contains(prefix, ".")
}
