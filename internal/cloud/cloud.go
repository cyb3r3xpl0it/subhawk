package cloud

import (
	"net"
	"strings"
)

type Provider struct {
	Name    string
	cnames  []string
	cidrStr []string
	cidrs   []*net.IPNet
}

var providers = []Provider{
	{
		Name:   "Cloudflare",
		cnames: []string{"cloudflare.com", "cloudflare.net"},
		cidrStr: []string{
			"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
			"104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
			"131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
			"172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
			"190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
		},
	},
	{
		Name:   "AWS CloudFront",
		cnames: []string{"cloudfront.net"},
	},
	{
		Name:   "AWS S3",
		cnames: []string{"s3.amazonaws.com", "s3-website"},
	},
	{
		Name:   "AWS ELB",
		cnames: []string{"elb.amazonaws.com", "elasticloadbalancing.amazonaws.com"},
	},
	{
		Name:   "AWS EC2",
		cnames: []string{"compute.amazonaws.com", "compute-1.amazonaws.com"},
	},
	{
		Name:   "Google Cloud",
		cnames: []string{"googleapis.com", "googleusercontent.com", "compute.google.com"},
	},
	{
		Name:   "Azure",
		cnames: []string{"azurewebsites.net", "cloudapp.azure.com", "cloudapp.net", "azurefd.net", "trafficmanager.net"},
	},
	{
		Name:   "Fastly",
		cnames: []string{"fastly.net", "fastlylb.net"},
	},
	{
		Name:   "Akamai",
		cnames: []string{"akamaiedge.net", "akamaitech.net", "akamaized.net"},
	},
	{
		Name:   "GitHub Pages",
		cnames: []string{"github.io", "githubusercontent.com"},
	},
	{
		Name:   "Vercel",
		cnames: []string{"vercel.app", "now.sh"},
	},
	{
		Name:   "Netlify",
		cnames: []string{"netlify.app", "netlify.com"},
	},
	{
		Name:   "Heroku",
		cnames: []string{"herokuapp.com", "herokussl.com"},
	},
	{
		Name:   "DigitalOcean",
		cnames: []string{"digitalocean.com", "ondigitalocean.app"},
	},
}

func init() {
	for i := range providers {
		for _, cidrStr := range providers[i].cidrStr {
			_, cidr, err := net.ParseCIDR(cidrStr)
			if err == nil {
				providers[i].cidrs = append(providers[i].cidrs, cidr)
			}
		}
	}
}

// Detect returns the cloud provider name for a given CNAME and IP list.
func Detect(cname string, ips []string) string {
	cname = strings.ToLower(cname)

	for _, p := range providers {
		for _, c := range p.cnames {
			if strings.Contains(cname, c) {
				return p.Name
			}
		}
		for _, ipStr := range ips {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			for _, cidr := range p.cidrs {
				if cidr.Contains(ip) {
					return p.Name
				}
			}
		}
	}
	return ""
}
