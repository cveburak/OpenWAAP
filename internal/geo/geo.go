package geo

import (
	"net"

	"github.com/oschwald/maxminddb-golang"
)

type Info struct {
	Country string
	ASN     uint32
	ASName  string
}

type Provider struct {
	db *maxminddb.Reader
}

type record struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	AutonomousSystemNumber       uint32 `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

func Open(path string) (*Provider, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &Provider{db: db}, nil
}

func (p *Provider) Lookup(ip net.IP) Info {
	if p == nil || p.db == nil || ip == nil {
		return Info{}
	}
	var rec record
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	if err := p.db.Lookup(ip, &rec); err != nil {
		return Info{}
	}
	return Info{Country: rec.Country.ISOCode, ASN: rec.AutonomousSystemNumber, ASName: rec.AutonomousSystemOrganization}
}

func (p *Provider) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	return p.db.Close()
}
