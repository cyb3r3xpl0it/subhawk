package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/cyb3r3xpl0it/subhawk/internal/resolver"
	_ "modernc.org/sqlite"
)

type DB struct {
	db *sql.DB
}

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		return nil, err
	}
	return &DB{db: db}, nil
}

func (s *DB) Close() error { return s.db.Close() }

func migrate(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS results (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		domain        TEXT NOT NULL,
		subdomain     TEXT NOT NULL,
		ips           TEXT,
		cname         TEXT,
		active        BOOLEAN,
		cloud         TEXT,
		open_ports    TEXT,
		waf           TEXT,
		http_status   INTEGER,
		http_url      TEXT,
		http_title    TEXT,
		http_server   TEXT,
		tech          TEXT,
		takeover      TEXT,
		cors_vuln     BOOLEAN,
		ssl_valid     BOOLEAN,
		ssl_expiry    INTEGER,
		favicon_hash  TEXT,
		asn           TEXT,
		asn_org       TEXT,
		country       TEXT,
		admin_panels  TEXT,
		js_secrets    TEXT,
		exposed_files TEXT,
		buckets       TEXT,
		open_redirects TEXT,
		default_creds  BOOLEAN,
		real_ip        TEXT,
		vhosts         TEXT,
		screenshot     TEXT,
		scan_time     TIMESTAMP,
		UNIQUE(domain, subdomain)
	)`)
	return err
}

func (s *DB) Save(domain string, r resolver.Result) error {
	ports := make([]string, len(r.OpenPorts))
	for i, p := range r.OpenPorts {
		ports[i] = fmt.Sprintf("%d", p)
	}

	httpStatus := 0
	httpURL, httpTitle, httpServer, tech := "", "", "", ""
	if r.HTTP != nil {
		httpStatus = r.HTTP.StatusCode
		httpURL = r.HTTP.URL
		httpTitle = r.HTTP.Title
		httpServer = r.HTTP.Server
		tech = strings.Join(r.HTTP.Tech, ",")
	}

	takeover := ""
	if r.Takeover != nil {
		takeover = r.Takeover.Service
	}

	corsVuln := false
	if r.CORS != nil {
		corsVuln = r.CORS.Vulnerable
	}

	sslValid := false
	sslExpiry := 0
	if r.TLS != nil {
		sslValid = r.TLS.Valid
		sslExpiry = r.TLS.DaysUntilExpiry
	}

	asnStr, asnOrg, country := "", "", ""
	if r.ASN != nil {
		asnStr = r.ASN.ASN
		asnOrg = r.ASN.Region
		country = r.ASN.Country
	}

	adminPanels := ""
	if len(r.AdminPanels) > 0 {
		panels := make([]string, len(r.AdminPanels))
		for i, p := range r.AdminPanels {
			panels[i] = p.URL
		}
		adminPanels = strings.Join(panels, ",")
	}

	jsSecrets := ""
	if r.JS != nil {
		jsSecrets = strings.Join(r.JS.Secrets, "|")
	}

	exposedFiles := ""
	if len(r.ExposedFiles) > 0 {
		ef := make([]string, len(r.ExposedFiles))
		for i, f := range r.ExposedFiles {
			ef[i] = f.Path
		}
		exposedFiles = strings.Join(ef, ",")
	}

	bucketsStr := ""
	for _, b := range r.Buckets {
		if b.Public {
			if bucketsStr != "" {
				bucketsStr += ","
			}
			bucketsStr += b.URL
		}
	}

	openRedirects := ""
	if len(r.OpenRedirects) > 0 {
		ors := make([]string, len(r.OpenRedirects))
		for i, or_ := range r.OpenRedirects {
			ors[i] = or_.URL
		}
		openRedirects = strings.Join(ors, ",")
	}

	hasCreds := len(r.DefaultCreds) > 0

	vhosts := strings.Join(r.VHosts, ",")

	_, err := s.db.Exec(`INSERT OR REPLACE INTO results
		(domain, subdomain, ips, cname, active, cloud, open_ports, waf,
		 http_status, http_url, http_title, http_server, tech,
		 takeover, cors_vuln, ssl_valid, ssl_expiry, favicon_hash,
		 asn, asn_org, country, admin_panels, js_secrets,
		 exposed_files, buckets, open_redirects, default_creds,
		 real_ip, vhosts, screenshot, scan_time)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		domain, r.Subdomain,
		strings.Join(r.IPs, ","), r.CNAME, r.Active, r.Cloud,
		strings.Join(ports, ","), r.WAF,
		httpStatus, httpURL, httpTitle, httpServer, tech,
		takeover, corsVuln, sslValid, sslExpiry, r.FaviconHash,
		asnStr, asnOrg, country, adminPanels, jsSecrets,
		exposedFiles, bucketsStr, openRedirects, hasCreds,
		r.RealIP, vhosts, r.ScreenshotPath,
		time.Now(),
	)
	return err
}
