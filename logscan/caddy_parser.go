package logscan

import (
	"encoding/json"
	"fmt"
	"math"
	"time"
)

type CaddyLogEntry struct {
	Timestamp   float64 `json:"ts"`
	Request     Request `json:"request"`
	Duration    float64 `json:"duration"`
	Size_       int     `json:"size"`
	Status_     int     `json:"status"`
	RespHeaders Headers `json:"resp_headers"`
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
}

func (p CaddyParser) Parse(line string) (Line, bool, error) {
	var logEntry CaddyLogEntry
	err := json.Unmarshal([]byte(line), &logEntry)
	if err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return nil, false, err
	}

	return logEntry, false, nil
}

var _ LineParser = CaddyParser{}
var _ Line = CaddyLogEntry{}

func (l CaddyLogEntry) Host() string       { return l.Request.Host }
func (l CaddyLogEntry) RemoteAddr() string { return l.Request.RemoteAddr }
func (l CaddyLogEntry) Method() string     { return l.Request.Method }
func (l CaddyLogEntry) HTTP() string       { return l.Request.Proto }
func (l CaddyLogEntry) Path() string       { return l.Request.URI }
func (l CaddyLogEntry) Status() int        { return l.Status_ }
func (l CaddyLogEntry) Size() int          { return l.Size_ }

func (l CaddyLogEntry) Query() string {
	return "" // TODO
}

func (l CaddyLogEntry) Timing() time.Duration {
	// TODO: `Second` should depend on the log format
	return time.Duration(l.Duration * float64(time.Second))
}

func (l CaddyLogEntry) Datetime(scan *Scanner) (time.Time, error) {
	sec, dec := math.Modf(l.Timestamp)
	t := time.Unix(int64(sec), int64(dec*(1e9)))
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
