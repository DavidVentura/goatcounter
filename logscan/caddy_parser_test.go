package logscan

import (
	"context"
	"io"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestParseLine(t *testing.T) {
	data, err := os.ReadFile("./caddy_testdata/1.json")
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
	dt, err := line.Datetime(p)
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

func TestParseLineDatetimeFormat(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()
	var testdata = []struct {
		format string
		input  string
		delta  time.Duration
	}{
		{"", `{"ts":1.5}`, 1500 * time.Millisecond}, // default value
		{"unix_seconds_float", `{"ts":1.5}`, 1500 * time.Millisecond},
		{"unix_milli_float", `{"ts":1500}`, 1500 * time.Millisecond},
		{"unix_milli_float", `{"ts":1500.1}`, 1_500_100 * time.Microsecond},
		{"unix_nano", `{"ts":1500000000}`, 1_500_000_000 * time.Nanosecond},
		{time.RFC3339, `{"ts":"1970-01-01T00:00:05+00:00"}`, 5 * time.Second},
	}
	for _, tt := range testdata {
		t.Run(tt.format, func(t *testing.T) {
			p := CaddyParser{datetime: tt.format}
			line, skip, err := p.Parse(tt.input)
			if skip {
				t.Fatalf("Entry skipped")
			}
			if err != nil {
				t.Fatalf("Failed to parse: %#v", err)
			}
			dt, err := line.Datetime(p)
			if err != nil {
				t.Fatalf("Failed to parse Datetime: %#v", err)
			}
			expected := epoch.Add(tt.delta)
			if dt.UTC() != expected.UTC() {
				t.Fatalf("Unexpected Datetime: %#v vs %#v", dt, expected)
			}
		})
	}
}

func TestParseUrl(t *testing.T) {
	p := CaddyParser{}
	line, skip, err := p.Parse(`{"request": {"uri": "//asd"}}`)
	if skip {
		t.Fatalf("Entry skipped")
	}
	if err != nil {
		t.Fatalf("Failed to parse: %#v", err)
	}
	if line.Path() != "//asd" {
		t.Fatalf("Unexpected Path: %#v", line.Path())
	}
}

func TestParseMultipleLines(t *testing.T) {
	want := []CaddyLogEntry{
		CaddyLogEntry{Timestamp: 1706788852.6825173,
			Request:     CaddyRequest{RemoteAddr: "1.2.3.4:41844", Proto: "HTTP/2.0", Method: "HEAD", Host: "host.example.com", URI: "/path.html", Headers: CaddyHeaders{UserAgent: []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"}, Referer: []string(nil), ContentType: []string(nil), XForwardedFor: []string(nil), AcceptLanguage: []string(nil)}},
			Duration:    0.000455129,
			Size_:       0,
			Status_:     304,
			RespHeaders: CaddyHeaders{UserAgent: []string(nil), Referer: []string(nil), ContentType: []string(nil), XForwardedFor: []string(nil), AcceptLanguage: []string(nil)}},
		CaddyLogEntry{Timestamp: 1706788853.7180748,
			Request:     CaddyRequest{RemoteAddr: "1.2.3.4:41844", Proto: "HTTP/2.0", Method: "HEAD", Host: "host.example.com", URI: "/path.html", Headers: CaddyHeaders{UserAgent: []string(nil), Referer: []string(nil), ContentType: []string(nil), XForwardedFor: []string(nil), AcceptLanguage: []string{"ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"}}},
			Duration:    0.000356122,
			Size_:       0,
			Status_:     304,
			RespHeaders: CaddyHeaders{UserAgent: []string(nil), Referer: []string(nil), ContentType: []string(nil), XForwardedFor: []string(nil), AcceptLanguage: []string(nil)}},
		CaddyLogEntry{Timestamp: 1706788854.7159958,
			Request:  CaddyRequest{RemoteAddr: "1.2.3.4:41844", Proto: "HTTP/2.0", Method: "HEAD", Host: "host.example.com", URI: "/path.html", Headers: CaddyHeaders{UserAgent: []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"}, Referer: []string(nil), ContentType: []string(nil), XForwardedFor: []string(nil), AcceptLanguage: []string{"ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"}}},
			Duration: 0.000728, Size_: 0, Status_: 304, RespHeaders: CaddyHeaders{UserAgent: []string(nil), Referer: []string(nil), ContentType: []string(nil), XForwardedFor: []string(nil), AcceptLanguage: []string(nil)}},
		CaddyLogEntry{Timestamp: 1706788855.7197819,
			Request:     CaddyRequest{RemoteAddr: "1.2.3.4:41844", Proto: "HTTP/2.0", Method: "HEAD", Host: "host.example.com", URI: "/path.html", Headers: CaddyHeaders{UserAgent: []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"}, Referer: []string(nil), ContentType: []string(nil), XForwardedFor: []string(nil), AcceptLanguage: []string{"ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"}}},
			Duration:    0.000275939,
			Size_:       0,
			Status_:     304,
			RespHeaders: CaddyHeaders{UserAgent: []string(nil), Referer: []string(nil), ContentType: []string(nil), XForwardedFor: []string(nil), AcceptLanguage: []string(nil)}},
		CaddyLogEntry{Timestamp: 1706788856.6911514,
			Request:     CaddyRequest{RemoteAddr: "1.2.3.4:41844", Proto: "HTTP/2.0", Method: "HEAD", Host: "host.example.com", URI: "/path.html", Headers: CaddyHeaders{UserAgent: []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"}, Referer: []string(nil), ContentType: []string(nil), XForwardedFor: []string(nil), AcceptLanguage: []string{"ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"}}},
			Duration:    0.000210732,
			Size_:       0,
			Status_:     304,
			RespHeaders: CaddyHeaders{UserAgent: []string(nil), Referer: []string(nil), ContentType: []string(nil), XForwardedFor: []string(nil), AcceptLanguage: []string(nil)},
		},
	}
	fp, err := os.Open("./caddy_testdata/2.json")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := New(fp, `caddy`, "", "", "", []string{})
	if err != nil {
		t.Fatal(err)
	}
	got := []CaddyLogEntry{}
	for {
		data, _, _, err := scan.Line(context.Background())
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, data.(CaddyLogEntry))
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("\ngot:  %#v\nwant: %#v", got, want)
	}
}
