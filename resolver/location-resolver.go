package resolver

import (
	"context"
	"github.com/1f349/azalea/database"
	"github.com/1f349/azalea/logger"
	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
	"net"
	"net/netip"
	"strings"
)

type GeoResolver struct {
	geo *geoip2.Reader
	db  *database.Queries
}

type LatLong struct {
	Lat  float64
	Long float64
}

func NewGeoResolver(geo *geoip2.Reader, db *database.Queries) *GeoResolver {
	return &GeoResolver{geo: geo, db: db}
}

func (l *GeoResolver) GetLatLong(ip net.IP) (LatLong, error) {
	city, err := l.geo.City(ip)
	if err != nil {
		return LatLong{}, err
	}
	return LatLong{
		Lat:  city.Location.Latitude,
		Long: city.Location.Longitude,
	}, nil
}

func (l *GeoResolver) GetBestLocation(ctx context.Context, name string, remoteIp net.IP) (database.GetBestLocationResolvedRecordRow, error) {
	loc, err := l.GetLatLong(remoteIp)
	if err != nil {
		return database.GetBestLocationResolvedRecordRow{}, err
	}
	return l.db.GetBestLocationResolvedRecord(ctx, database.GetBestLocationResolvedRecordParams{
		Lat:  loc.Lat,
		Long: loc.Long,
		Name: name,
	})
}

// TODO(melon): add tests for this
func (l *GeoResolver) GeoResolvedRecords(ctx context.Context, name string, remoteIp net.IP) ([]dns.RR, error) {
	resolvedRecord, err := l.GetBestLocation(ctx, name, remoteIp)
	logger.Logger.Info("hi", "rec", resolvedRecord, "err", err, "name", name, "ip", remoteIp)
	if err != nil {
		return nil, err
	}
	sep := strings.Split(resolvedRecord.Value, ",")
	var rrs []dns.RR
	for _, i := range sep {
		ip, err := netip.ParseAddr(i)
		if err != nil {
			return nil, err
		}
		if ip.Is4() {
			rrs = append(rrs, &dns.A{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: ip.AsSlice(),
			})
		} else if ip.Is6() {
			rrs = append(rrs, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: ip.AsSlice(),
			})
		}
	}
	return rrs, nil
}
