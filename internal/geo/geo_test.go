package geo

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func writeFixture(t *testing.T) string {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "GeoLite2-Country",
		RecordSize:              24,
		IncludeReservedNetworks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, tr, _ := net.ParseCIDR("81.2.69.0/24")
	if err := w.Insert(tr, mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String("GB"),
		},
		"autonomous_system_number":       mmdbtype.Uint32(5089),
		"autonomous_system_organization": mmdbtype.String("ExampleCo"),
	}); err != nil {
		t.Fatal(err)
	}
	_, de, _ := net.ParseCIDR("2001:4b0::/32")
	if err := w.Insert(de, mmdbtype.Map{
		"country":                        mmdbtype.Map{"iso_code": mmdbtype.String("DE")},
		"autonomous_system_number":       mmdbtype.Uint32(3320),
		"autonomous_system_organization": mmdbtype.String("ExampleNet"),
		"some_unused_field":              mmdbtype.Map{"deep": mmdbtype.String("ignored")},
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.mmdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLookup(t *testing.T) {
	p, err := Open(writeFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if got := p.Lookup(net.ParseIP("81.2.69.160")); got.Country != "GB" || got.ASN != 5089 || got.ASName != "ExampleCo" {
		t.Fatalf("v4 lookup wrong: %+v", got)
	}
	if got := p.Lookup(net.ParseIP("2001:4b0:1:2::3")); got.Country != "DE" || got.ASN != 3320 {
		t.Fatalf("v6 lookup wrong: %+v", got)
	}
	if got := p.Lookup(net.ParseIP("10.0.0.1")); got.Country != "" || got.ASN != 0 {
		t.Fatalf("private IP must be unknown: %+v", got)
	}
	if got := p.Lookup(nil); got.Country != "" {
		t.Fatalf("nil IP must be unknown")
	}
}

func TestOpenMissingFile(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "nope.mmdb")); err == nil {
		t.Fatal("opening a missing database must fail fast")
	}
}

func TestNilProviderSafe(t *testing.T) {
	var p *Provider
	if got := p.Lookup(net.ParseIP("8.8.8.8")); got.Country != "" {
		t.Fatalf("nil provider must be inert")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("nil close must be inert: %v", err)
	}
}
