package headers

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Info struct {
	HSTS              bool
	CSP               bool
	XFrameOptions     bool
	XContentTypeOpts  bool
	ReferrerPolicy    bool
	PermissionsPolicy bool
	XXSSProtection    bool
	Missing           []string
	Score             int // 0-100
}

var client = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func Audit(subdomain string) *Info {
	for _, scheme := range []string{"https", "http"} {
		resp, err := client.Get(fmt.Sprintf("%s://%s", scheme, subdomain))
		if err != nil {
			continue
		}
		resp.Body.Close()
		return analyze(resp)
	}
	return nil
}

func analyze(resp *http.Response) *Info {
	h := resp.Header
	info := &Info{
		HSTS:              h.Get("Strict-Transport-Security") != "",
		CSP:               h.Get("Content-Security-Policy") != "",
		XFrameOptions:     h.Get("X-Frame-Options") != "",
		XContentTypeOpts:  strings.EqualFold(h.Get("X-Content-Type-Options"), "nosniff"),
		ReferrerPolicy:    h.Get("Referrer-Policy") != "",
		PermissionsPolicy: h.Get("Permissions-Policy") != "",
		XXSSProtection:    h.Get("X-XSS-Protection") != "",
	}

	checks := []struct {
		present bool
		name    string
		points  int
	}{
		{info.HSTS, "Strict-Transport-Security", 20},
		{info.CSP, "Content-Security-Policy", 25},
		{info.XFrameOptions, "X-Frame-Options", 15},
		{info.XContentTypeOpts, "X-Content-Type-Options", 15},
		{info.ReferrerPolicy, "Referrer-Policy", 10},
		{info.PermissionsPolicy, "Permissions-Policy", 10},
		{info.XXSSProtection, "X-XSS-Protection", 5},
	}

	for _, c := range checks {
		if c.present {
			info.Score += c.points
		} else {
			info.Missing = append(info.Missing, c.name)
		}
	}

	return info
}
