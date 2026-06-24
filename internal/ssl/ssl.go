package ssl

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

type Info struct {
	Valid            bool
	SelfSigned       bool
	Expired          bool
	HostnameMismatch bool
	DaysUntilExpiry  int
	Version          string
	Issuer           string
	Subject          string
	SANs             []string
	WeakProtocol     bool
}

func Audit(subdomain string) *Info {
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	// First try with verification to detect issues
	conf := &tls.Config{ServerName: subdomain}
	conn, err := tls.DialWithDialer(dialer, "tcp", subdomain+":443", conf)

	info := &Info{}

	if err != nil {
		errStr := err.Error()
		switch {
		case strings.Contains(errStr, "certificate has expired"):
			info.Expired = true
		case strings.Contains(errStr, "certificate signed by unknown authority"):
			info.SelfSigned = true
		case strings.Contains(errStr, "certificate is not valid for"):
			info.HostnameMismatch = true
		}
		// Retry without verification to get cert details anyway
		conn, err = tls.DialWithDialer(dialer, "tcp", subdomain+":443",
			&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil
		}
	} else {
		info.Valid = true
	}
	defer conn.Close()

	state := conn.ConnectionState()
	info.Version = tlsVersionName(state.Version)
	info.WeakProtocol = state.Version < tls.VersionTLS12

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.Subject = cert.Subject.CommonName
		info.Issuer = cert.Issuer.CommonName
		info.SANs = cert.DNSNames
		info.DaysUntilExpiry = int(time.Until(cert.NotAfter).Hours() / 24)
		if info.DaysUntilExpiry < 0 {
			info.Expired = true
		}

		// Detect self-signed
		if cert.Issuer.String() == cert.Subject.String() {
			info.SelfSigned = true
		}

		// Check hostname manually if not already flagged
		if !info.HostnameMismatch && !info.Valid {
			if err := cert.VerifyHostname(subdomain); err != nil {
				info.HostnameMismatch = true
			}
		}

		// Check against trusted roots
		if !info.SelfSigned {
			opts := x509.VerifyOptions{DNSName: subdomain}
			if _, err := cert.Verify(opts); err == nil {
				info.Valid = true
			}
		}
	}

	return info
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
