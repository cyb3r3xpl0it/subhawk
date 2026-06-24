package takeover

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cyb3r3xpl0it/subhawk/internal/resolver"
)

type fingerprint struct {
	service string
	cnames  []string
	bodies  []string
}

var fingerprints = []fingerprint{
	{
		service: "GitHub Pages",
		cnames:  []string{"github.io", "githubusercontent.com"},
		bodies:  []string{"There isn't a GitHub Pages site here"},
	},
	{
		service: "Heroku",
		cnames:  []string{"herokuapp.com", "herokussl.com"},
		bodies:  []string{"No such app"},
	},
	{
		service: "Amazon S3",
		cnames:  []string{"s3.amazonaws.com", "s3-website"},
		bodies:  []string{"NoSuchBucket", "The specified bucket does not exist"},
	},
	{
		service: "Netlify",
		cnames:  []string{"netlify.app", "netlify.com"},
		bodies:  []string{"Not Found - Request ID"},
	},
	{
		service: "Vercel",
		cnames:  []string{"vercel.app", "now.sh"},
		bodies:  []string{"The deployment could not be found", "DEPLOYMENT_NOT_FOUND"},
	},
	{
		service: "Fastly",
		cnames:  []string{"fastly.net"},
		bodies:  []string{"Fastly error: unknown domain"},
	},
	{
		service: "Shopify",
		cnames:  []string{"myshopify.com"},
		bodies:  []string{"Sorry, this shop is currently unavailable"},
	},
	{
		service: "Tumblr",
		cnames:  []string{"tumblr.com"},
		bodies:  []string{"There's nothing here"},
	},
	{
		service: "Zendesk",
		cnames:  []string{"zendesk.com"},
		bodies:  []string{"Help Center Closed"},
	},
	{
		service: "Freshdesk",
		cnames:  []string{"freshdesk.com"},
		bodies:  []string{"We couldn't find the page you were looking for"},
	},
	{
		service: "Surge.sh",
		cnames:  []string{"surge.sh"},
		bodies:  []string{"project not found"},
	},
	{
		service: "readme.io",
		cnames:  []string{"readme.io", "readmessl.com"},
		bodies:  []string{"Project doesnt exist", "Project not found"},
	},
	{
		service: "Ghost",
		cnames:  []string{"ghost.io"},
		bodies:  []string{"The thing you were looking for is no longer here"},
	},
	{
		service: "Azure",
		cnames:  []string{"azurewebsites.net", "cloudapp.net", "cloudapp.azure.com"},
		bodies:  []string{"404 Web Site not found"},
	},
	{
		service: "Bitbucket",
		cnames:  []string{"bitbucket.io"},
		bodies:  []string{"Repository not found"},
	},
	{
		service: "HubSpot",
		cnames:  []string{"hubspot.net", "hs-sites.com"},
		bodies:  []string{"Domain not found"},
	},
	{
		service: "Intercom",
		cnames:  []string{"custom.intercom.help"},
		bodies:  []string{"This page is reserved for artistic dogs"},
	},
	{
		service: "Webflow",
		cnames:  []string{"webflow.io"},
		bodies:  []string{"The page you are looking for doesn't exist"},
	},
}

var httpClient = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// Check evaluates a resolved subdomain for takeover vulnerability.
func Check(r resolver.Result) *resolver.TakeoverInfo {
	cname := strings.ToLower(r.CNAME)

	for _, fp := range fingerprints {
		// CNAME match
		for _, c := range fp.cnames {
			if strings.Contains(cname, c) {
				// Confirm with body check
				if info := bodyCheck(r.Subdomain, fp.bodies); info != nil {
					return &resolver.TakeoverInfo{
						Service:     fp.service,
						Fingerprint: info.matched,
					}
				}
			}
		}
	}
	return nil
}

type bodyResult struct {
	matched string
}

func bodyCheck(subdomain string, patterns []string) *bodyResult {
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, subdomain)
		resp, err := httpClient.Get(url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()

		bodyStr := string(body)
		for _, pattern := range patterns {
			if strings.Contains(bodyStr, pattern) {
				return &bodyResult{matched: pattern}
			}
		}
		return nil
	}
	return nil
}
