package logscan

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
)

// https://caddyserver.com/docs/caddyfile/directives/log
type CaddyLogEntry struct {
	Timestamp   interface{} `json:"ts"`
	Request     Request     `json:"request"`
	Duration    float64     `json:"duration"`
	Size_       int         `json:"size"`
	Status_     int         `json:"status"`
	RespHeaders Headers     `json:"resp_headers"`
}

type Request struct {
	RemoteAddr string  `json:"remote_addr"`
	Proto      string  `json:"proto"`
	Method     string  `json:"method"`
	Host       string  `json:"host"`
	URI        string  `json:"uri"`
	Headers    Headers `json:"headers"`
}

type Headers struct {
	UserAgent      []string `json:"User-Agent"`
	Referer        []string `json:"Referer"`
	ContentType    []string `json:"Content-Type"`
	XForwardedFor  []string `json:"X-Forwarded-For"`
	AcceptLanguage []string `json:"Accept-Language"`
}

type CaddyParser struct {
	datetime        string
	excludePatterns []excludePattern
}

func (p CaddyParser) Parse(line string) (Line, bool, error) {
	var logEntry CaddyLogEntry
	err := json.Unmarshal([]byte(line), &logEntry)
	if err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return nil, false, err
	}

	for _, e := range p.excludePatterns {
		if logEntry.matchesPattern(e) {
			return nil, true, nil
		}
	}
	return logEntry, false, nil
}

var _ LineParser = CaddyParser{}
var _ Line = CaddyLogEntry{}

func (l CaddyLogEntry) Host() string       { return l.Request.Host }
func (l CaddyLogEntry) RemoteAddr() string { return l.Request.RemoteAddr }
func (l CaddyLogEntry) Method() string     { return l.Request.Method }
func (l CaddyLogEntry) HTTP() string       { return l.Request.Proto }
func (l CaddyLogEntry) Status() int        { return l.Status_ }
func (l CaddyLogEntry) Size() int          { return l.Size_ }
func (l CaddyLogEntry) Path() string {
	u, err := url.ParseRequestURI(l.Request.URI)
	if err != nil {
		return ""
	}
	return u.Path
}

func (l CaddyLogEntry) Query() string {
	u, err := url.Parse(l.Request.URI)
	if err != nil {
		return ""
	}
	return u.RawQuery
}

func (l CaddyLogEntry) Timing() time.Duration {
	// TODO: `Second` should depend on the log format
	// {seconds, nano, string} where string in {1m32.05s, 6.31ms}
	return time.Duration(l.Duration * float64(time.Second))
}

func (l CaddyLogEntry) Datetime(lp LineParser) (time.Time, error) {
	/* time_format can be

	   - unix_seconds_float Floating-point number of seconds since the Unix epoch.
	   - unix_milli_float 	Floating-point number of milliseconds since the Unix epoch.
	   - unix_nano 			Integer number of nanoseconds since the Unix epoch.
	   - iso8601 			Example: 2006-01-02T15:04:05.000Z0700
	   - rfc3339 			Example: 2006-01-02T15:04:05Z07:00
	   - rfc3339_nano 		Example: 2006-01-02T15:04:05.999999999Z07:00
	   - wall 				Example: 2006/01/02 15:04:05
	   - wall_milli 		Example: 2006/01/02 15:04:05.000
	   - wall_nano 			Example: 2006/01/02 15:04:05.000000000
	   - common_log 		Example: 02/Jan/2006:15:04:05 -0700

	   Or, any compatible time layout string; see the Go documentation for full details.
	*/

	parser := lp.(CaddyParser)
	var t time.Time
	var err error
	switch parser.datetime {
	case "", "unix_seconds_float":
		// Caddy's default
		v := l.Timestamp.(float64)
		sec, dec := math.Modf(v)
		t = time.Unix(int64(sec), int64(dec*(1e9)))
	case "unix_milli_float":
		v := l.Timestamp.(float64)
		sec, dec := math.Modf(v / 1000)
		t = time.Unix(int64(sec), int64(dec*(1e9)))
	case "unix_nano":
		v := l.Timestamp.(float64)
		t = time.UnixMicro(int64(v / 1000))
	default:
		v := l.Timestamp.(string)
		t, err = time.Parse(parser.datetime, v)
		if err != nil {
			return time.Unix(0, 0).UTC(), err
		}
	}
	return t, nil
}
func (l CaddyLogEntry) XForwardedFor() string {
	if len(l.Request.Headers.XForwardedFor) > 0 {
		return l.Request.Headers.XForwardedFor[0]
	}
	return ""
}
func (l CaddyLogEntry) Referrer() string {
	if len(l.Request.Headers.Referer) > 0 {
		return l.Request.Headers.Referer[0]
	}
	return ""
}
func (l CaddyLogEntry) UserAgent() string {
	if len(l.Request.Headers.UserAgent) > 0 {
		return l.Request.Headers.UserAgent[0]
	}
	return ""
}
func (l CaddyLogEntry) ContentType() string {
	if len(l.Request.Headers.ContentType) > 0 {
		return l.Request.Headers.ContentType[0]
	}
	return ""
}
func (l CaddyLogEntry) Language() string {
	if len(l.Request.Headers.AcceptLanguage) > 0 {
		return l.Request.Headers.AcceptLanguage[0]
	}
	return ""
}

func (l CaddyLogEntry) fieldValue(name string) string {
	switch name {
	default:
		panic(fmt.Sprintf("Received invalid field request: %s", name))
	case fieldUserAgent:
		return l.UserAgent()
	case fieldHost:
		return l.Host()
	case fieldRemoteAddr:
		return l.RemoteAddr()
	case fieldAcceptLanguage:
		return l.Language()
	case fieldContentType:
		return l.ContentType()
	case fieldHttp:
		return l.HTTP()
	case fieldMethod:
		return l.Method()
	case fieldPath:
		return l.Path()
	case fieldQuery:
		return l.Query()
	case fieldReferrer:
		return l.Referrer()
	case fieldSize:
		return fmt.Sprint(l.Size())
	case fieldStatus:
		return fmt.Sprint(l.Status())
	case fieldXff:
		return l.XForwardedFor()
	}
}

func (l CaddyLogEntry) matchesPattern(e excludePattern) bool {
	var m bool
	fieldValue := l.fieldValue(e.field)
	switch e.kind {
	default:
		m = strings.Contains(fieldValue, e.pattern)
	case excludeGlob:
		// We use doublestar instead of filepath.Match() because the latter
		// doesn't support "**" and "{a,b}" patterns, both of which are very
		// useful here.
		m, _ = doublestar.Match(e.pattern, fieldValue)
	case excludeRe:
		m = e.re.MatchString(fieldValue)
	}
	if e.negate {
		return !m
	}
	return m
}
