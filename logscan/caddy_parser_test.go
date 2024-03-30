package logscan

import (
	"io/ioutil"
	"testing"
	"time"
)

func TestParseLine(t *testing.T) {
	data, err := ioutil.ReadFile("./caddy_testdata/1.json")
	if err != nil {
		t.Fatal(err)
	}
	p := CaddyParser{}
	line, skip, err := p.Parse(string(data))
	if skip {
		t.Fatalf("Entry skipped")
	}
	if err != nil {
		t.Fatalf("Failed to parse: %#v", err)
	}

	if line.Host() != "host.example.com" {
		t.Fatalf("Unexpected Host: %#v", line.Host())
	}
	if line.RemoteAddr() != "1.2.3.4:5678" {
		t.Fatalf("Unexpected RemoteAddr: %#v", line.RemoteAddr())
	}
	if line.Method() != "GET" {
		t.Fatalf("Unexpected Method: %#v", line.Method())
	}
	if line.HTTP() != "HTTP/1.1" {
		t.Fatalf("Unexpected HTTP: %#v", line.HTTP())
	}
	if line.Path() != "/absolute_uri.html" {
		t.Fatalf("Unexpected Path: %#v", line.Path())
	}
	if line.Status() != 200 {
		t.Fatalf("Unexpected Status: %#v", line.Status())
	}
	if line.Size() != 2803 {
		t.Fatalf("Unexpected Size: %#v", line.Size())
	}
	if line.Query() != "queryparam=value" {
		t.Fatalf("Unexpected Query: %#v", line.Query())
	}
	if line.Timing() != 1234567 {
		t.Fatalf("Unexpected Timing: %#v", line.Timing())
	}
	dt, err := line.Datetime(nil)
	if err != nil {
		t.Fatalf("Failed to parse Datetime: %#v", err)
	}
	if dt != time.Date(2024, 02, 01, 14, 32, 01, 656359195, time.Local) {
		t.Fatalf("Unexpected Datetime: %#v", dt)
	}
	if line.XForwardedFor() != "" {
		t.Fatalf("Unexpected XForwardedFor: %#v", line.XForwardedFor())
	}
	if line.Referrer() != "https://another.example.com/" {
		t.Fatalf("Unexpected Referrer: %#v", line.Referrer())
	}
	if line.UserAgent() != "This is the user agent" {
		t.Fatalf("Unexpected UserAgent: %#v", line.UserAgent())
	}
	if line.ContentType() != "" {
		t.Fatalf("Unexpected ContentType: %#v", line.ContentType())
	}
	if line.Language() != "en" {
		t.Fatalf("Unexpected Language: %#v", line.Language())
	}
}
