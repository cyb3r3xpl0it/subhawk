package emailscore

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type Score struct {
	SPF       int
	DMARC     int
	DKIM      int
	Total     int
	Grade     string
	SPFRecord  string
	DMARCRecord string
	DKIMFound  bool
}

var dkimSelectors = []string{
	"default", "google", "mail", "k1", "k2",
	"selector1", "selector2", "dkim", "smtp",
	"mandrill", "mailjet", "sendgrid", "mg",
}

func Calculate(domain string) *Score {
	s := &Score{}
	r := &net.Resolver{PreferGo: true}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// SPF — query TXT on root domain
	if txts, err := r.LookupTXT(ctx, domain); err == nil {
		for _, txt := range txts {
			if strings.HasPrefix(txt, "v=spf1") {
				s.SPFRecord = txt
				switch {
				case strings.Contains(txt, "-all"):
					s.SPF = 33
				case strings.Contains(txt, "~all"):
					s.SPF = 20
				case strings.Contains(txt, "?all") || strings.Contains(txt, "+all"):
					s.SPF = 5
				default:
					s.SPF = 10
				}
				break
			}
		}
	}

	// DMARC — query _dmarc.domain TXT
	if txts, err := r.LookupTXT(ctx, "_dmarc."+domain); err == nil {
		for _, txt := range txts {
			if strings.HasPrefix(txt, "v=DMARC1") {
				s.DMARCRecord = txt
				switch {
				case strings.Contains(txt, "p=reject"):
					s.DMARC = 33
				case strings.Contains(txt, "p=quarantine"):
					s.DMARC = 20
				case strings.Contains(txt, "p=none"):
					s.DMARC = 5
				}
				break
			}
		}
	}

	// DKIM — try common selectors
	for _, sel := range dkimSelectors {
		target := fmt.Sprintf("%s._domainkey.%s", sel, domain)
		if txts, err := r.LookupTXT(ctx, target); err == nil && len(txts) > 0 {
			for _, t := range txts {
				if strings.Contains(t, "v=DKIM1") || strings.Contains(t, "p=") {
					s.DKIMFound = true
					s.DKIM = 34
					break
				}
			}
		}
		if s.DKIMFound {
			break
		}
	}

	s.Total = s.SPF + s.DMARC + s.DKIM
	s.Grade = grade(s.Total)
	return s
}

func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}
