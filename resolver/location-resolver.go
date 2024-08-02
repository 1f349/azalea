package resolver

import (
	"context"
	"errors"
	"github.com/1f349/azalea/database"
	"github.com/1f349/azalea/logger"
	"github.com/1f349/azalea/models"
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
	if l.geo == nil {
		return LatLong{}, errors.New("geoip is not enabled")
	}
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
		Column1: loc.Lat,
		Column2: loc.Long,
		Name:    name,
	})
}

// GeoResolvedRecords returns the record for a service name closest to the remoteIp
// TODO(melon): add tests for this
func (l *GeoResolver) GeoResolvedRecords(ctx context.Context, name string, remoteIp net.IP) ([]*models.Record, error) {
	resolvedRecord, err := l.GetBestLocation(ctx, name, remoteIp)
	logger.Logger.Info("hi", "rec", resolvedRecord, "err", err, "name", name, "ip", remoteIp)
	if err != nil {
		return nil, err
	}
	sep := strings.Split(resolvedRecord.Value, ",")
	var rrs []*models.Record
	for _, i := range sep {
		ip, err := netip.ParseAddr(i)
		if err != nil {
			return nil, err
		}
		if ip.Is4() {
			rrs = append(rrs, &models.Record{
				Name:  name,
				Type:  dns.TypeA,
				Value: &models.A{IP: ip.AsSlice()},
			})
		} else if ip.Is6() {
			rrs = append(rrs, &models.Record{
				Name:  name,
				Type:  dns.TypeAAAA,
				Value: &models.AAAA{IP: ip.AsSlice()},
			})
		}
	}
	return rrs, nil
}
