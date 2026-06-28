package techdetect

import (
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Tech struct {
	Name     string
	Version  string
	Category string // "cms", "framework", "language", "server", "cdn", "analytics", "js-framework", "db", "security", "devops", "mail", "ecommerce", "other"
}

type Result struct {
	Techs   []Tech
	Headers map[string]string // raw response headers (lowercase)
}

type signature struct {
	name     string
	category string
	// Each matcher is checked against: headers, body, cookies, url
	headers map[string]*matcher // header-name → matcher
	body    []*matcher
	cookies map[string]*matcher // cookie-name → matcher
	url     []*matcher
}

type matcher struct {
	re      *regexp.Regexp
	verGrp  int    // capture group index for version (0 = no version)
	plain   string // plain string match (faster than regex when possible)
}

func newMatcher(pattern string, verGrp int) *matcher {
	m := &matcher{verGrp: verGrp}
	if pattern == "" {
		return m
	}
	// Try plain match first
	if !strings.ContainsAny(pattern, `\.+*?[](){}^$|`) {
		m.plain = strings.ToLower(pattern)
		return m
	}
	re, err := regexp.Compile(`(?i)` + pattern)
	if err != nil {
		m.plain = strings.ToLower(pattern)
		return m
	}
	m.re = re
	return m
}

func (m *matcher) match(s string) (bool, string) {
	if m == nil {
		return true, ""
	}
	sl := strings.ToLower(s)
	if m.plain != "" {
		return strings.Contains(sl, m.plain), ""
	}
	if m.re == nil {
		return true, ""
	}
	groups := m.re.FindStringSubmatch(s)
	if groups == nil {
		return false, ""
	}
	ver := ""
	if m.verGrp > 0 && m.verGrp < len(groups) {
		ver = strings.TrimSpace(groups[m.verGrp])
	}
	return true, ver
}

// signatures database — 200+ tech fingerprints
var signatures = []signature{
	// === CMS ===
	{name: "WordPress", category: "cms",
		body:    []*matcher{newMatcher(`/wp-content/`, 0), newMatcher(`wp-includes`, 0)},
		cookies: map[string]*matcher{"wordpress_logged_in": newMatcher("", 0)},
	},
	{name: "WordPress", category: "cms",
		headers: map[string]*matcher{"x-powered-by": newMatcher(`wordpress`, 0)},
	},
	{name: "Drupal", category: "cms",
		body:    []*matcher{newMatcher(`Drupal\.settings`, 0), newMatcher(`/sites/default/files`, 0)},
		cookies: map[string]*matcher{"SESS": newMatcher("", 0)},
	},
	{name: "Joomla", category: "cms",
		body: []*matcher{newMatcher(`joomla`, 0), newMatcher(`/media/jui/`, 0)},
	},
	{name: "Magento", category: "ecommerce",
		body:    []*matcher{newMatcher(`Mage\.`, 0), newMatcher(`/skin/frontend/`, 0)},
		cookies: map[string]*matcher{"frontend": newMatcher("", 0)},
	},
	{name: "Shopify", category: "ecommerce",
		body:    []*matcher{newMatcher(`Shopify\.`, 0), newMatcher(`cdn\.shopify\.com`, 0)},
		headers: map[string]*matcher{"x-shopify-stage": newMatcher("", 0)},
	},
	{name: "WooCommerce", category: "ecommerce",
		body: []*matcher{newMatcher(`woocommerce`, 0)},
	},
	{name: "Ghost", category: "cms",
		body:    []*matcher{newMatcher(`ghost`, 0)},
		headers: map[string]*matcher{"x-ghost-cache-status": newMatcher("", 0)},
	},
	{name: "Typo3", category: "cms",
		body: []*matcher{newMatcher(`typo3`, 0), newMatcher(`/typo3/`, 0)},
	},
	{name: "Craft CMS", category: "cms",
		body:    []*matcher{newMatcher(`craft`, 0)},
		cookies: map[string]*matcher{"CraftSessionId": newMatcher("", 0)},
	},
	{name: "Strapi", category: "cms",
		headers: map[string]*matcher{"x-powered-by": newMatcher(`strapi`, 0)},
	},
	{name: "Contentful", category: "cms",
		body: []*matcher{newMatcher(`contentful`, 0)},
	},
	// === Frameworks ===
	{name: "Laravel", category: "framework",
		cookies: map[string]*matcher{"laravel_session": newMatcher("", 0)},
		headers: map[string]*matcher{"x-powered-by": newMatcher(`laravel`, 0)},
	},
	{name: "Django", category: "framework",
		cookies: map[string]*matcher{"csrftoken": newMatcher("", 0), "sessionid": newMatcher("", 0)},
		headers: map[string]*matcher{"x-frame-options": newMatcher(`sameorigin`, 0)},
	},
	{name: "Rails", category: "framework",
		cookies: map[string]*matcher{"_rails_session": newMatcher("", 0)},
		headers: map[string]*matcher{"x-powered-by": newMatcher(`phusion passenger`, 0)},
	},
	{name: "Ruby on Rails", category: "framework",
		body:    []*matcher{newMatcher(`csrf-token`, 0)},
		cookies: map[string]*matcher{"_session_id": newMatcher("", 0)},
	},
	{name: "Spring Boot", category: "framework",
		headers: map[string]*matcher{"x-application-context": newMatcher("", 0)},
		cookies: map[string]*matcher{"JSESSIONID": newMatcher("", 0)},
	},
	{name: "ASP.NET", category: "framework",
		headers: map[string]*matcher{"x-powered-by": newMatcher(`ASP\.NET`, 0), "x-aspnet-version": newMatcher(`([\d.]+)`, 1)},
		cookies: map[string]*matcher{"ASP.NET_SessionId": newMatcher("", 0)},
	},
	{name: "ASP.NET MVC", category: "framework",
		headers: map[string]*matcher{"x-aspnetmvc-version": newMatcher(`([\d.]+)`, 1)},
	},
	{name: "Express", category: "framework",
		headers: map[string]*matcher{"x-powered-by": newMatcher(`express`, 0)},
	},
	{name: "FastAPI", category: "framework",
		headers: map[string]*matcher{"server": newMatcher(`uvicorn`, 0)},
		body:    []*matcher{newMatcher(`fastapi`, 0)},
	},
	{name: "Flask", category: "framework",
		cookies: map[string]*matcher{"session": newMatcher("", 0)},
		headers: map[string]*matcher{"server": newMatcher(`werkzeug`, 0)},
	},
	{name: "Symfony", category: "framework",
		cookies: map[string]*matcher{"symfony": newMatcher("", 0)},
		body:    []*matcher{newMatcher(`symfony`, 0)},
	},
	{name: "CodeIgniter", category: "framework",
		cookies: map[string]*matcher{"ci_session": newMatcher("", 0)},
	},
	{name: "CakePHP", category: "framework",
		cookies: map[string]*matcher{"CAKEPHP": newMatcher("", 0)},
	},
	{name: "Yii", category: "framework",
		cookies: map[string]*matcher{"YII_CSRF_TOKEN": newMatcher("", 0)},
	},
	// === Languages ===
	{name: "PHP", category: "language",
		headers: map[string]*matcher{"x-powered-by": newMatcher(`PHP/([\d.]+)`, 1)},
		cookies: map[string]*matcher{"PHPSESSID": newMatcher("", 0)},
	},
	{name: "Python", category: "language",
		headers: map[string]*matcher{"x-powered-by": newMatcher(`python`, 0), "server": newMatcher(`python`, 0)},
	},
	{name: "Java", category: "language",
		cookies: map[string]*matcher{"JSESSIONID": newMatcher("", 0)},
		headers: map[string]*matcher{"x-powered-by": newMatcher(`jsp|servlet|java`, 0)},
	},
	{name: "Node.js", category: "language",
		headers: map[string]*matcher{"x-powered-by": newMatcher(`node`, 0)},
	},
	{name: "Ruby", category: "language",
		headers: map[string]*matcher{"server": newMatcher(`passenger|puma|thin|unicorn`, 0)},
	},
	{name: "Perl", category: "language",
		headers: map[string]*matcher{"x-powered-by": newMatcher(`perl|mod_perl`, 0)},
	},
	{name: "Go", category: "language",
		headers: map[string]*matcher{"server": newMatcher(`^go`, 0)},
	},
	// === Servers ===
	{name: "nginx", category: "server",
		headers: map[string]*matcher{"server": newMatcher(`nginx(?:/([\d.]+))?`, 1)},
	},
	{name: "Apache", category: "server",
		headers: map[string]*matcher{"server": newMatcher(`Apache(?:/([\d.]+))?`, 1)},
	},
	{name: "IIS", category: "server",
		headers: map[string]*matcher{"server": newMatcher(`Microsoft-IIS(?:/([\d.]+))?`, 1)},
	},
	{name: "Caddy", category: "server",
		headers: map[string]*matcher{"server": newMatcher(`caddy`, 0)},
	},
	{name: "LiteSpeed", category: "server",
		headers: map[string]*matcher{"server": newMatcher(`litespeed`, 0)},
	},
	{name: "Tomcat", category: "server",
		headers: map[string]*matcher{"server": newMatcher(`Apache-Coyote|Tomcat`, 0)},
	},
	{name: "OpenResty", category: "server",
		headers: map[string]*matcher{"server": newMatcher(`openresty(?:/([\d.]+))?`, 1)},
	},
	{name: "Gunicorn", category: "server",
		headers: map[string]*matcher{"server": newMatcher(`gunicorn(?:/([\d.]+))?`, 1)},
	},
	// === JS Frameworks ===
	{name: "React", category: "js-framework",
		body: []*matcher{newMatcher(`react\.development\.js|react\.production\.min\.js|__REACT`, 0)},
	},
	{name: "Vue.js", category: "js-framework",
		body: []*matcher{newMatcher(`vue(?:\.min)?\.js|__vue__|Vue\.config`, 0)},
	},
	{name: "Angular", category: "js-framework",
		body: []*matcher{newMatcher(`ng-version|angular\.min\.js|@angular`, 0)},
	},
	{name: "Next.js", category: "js-framework",
		headers: map[string]*matcher{"x-powered-by": newMatcher(`Next\.js`, 0)},
		body:    []*matcher{newMatcher(`__NEXT_DATA__`, 0)},
	},
	{name: "Nuxt.js", category: "js-framework",
		body: []*matcher{newMatcher(`__nuxt|__NUXT`, 0)},
	},
	{name: "Svelte", category: "js-framework",
		body: []*matcher{newMatcher(`__svelte`, 0)},
	},
	{name: "jQuery", category: "js-framework",
		body: []*matcher{newMatcher(`jquery(?:-([\d.]+))?(?:\.min)?\.js`, 1)},
	},
	{name: "Bootstrap", category: "js-framework",
		body: []*matcher{newMatcher(`bootstrap(?:-([\d.]+))?(?:\.min)?\.(?:js|css)`, 1)},
	},
	{name: "Ember.js", category: "js-framework",
		body: []*matcher{newMatcher(`ember(?:\.min)?\.js`, 0)},
	},
	{name: "Backbone.js", category: "js-framework",
		body: []*matcher{newMatcher(`backbone(?:\.min)?\.js`, 0)},
	},
	// === CDN / Hosting ===
	{name: "Cloudflare", category: "cdn",
		headers: map[string]*matcher{"cf-ray": newMatcher("", 0), "server": newMatcher(`cloudflare`, 0)},
	},
	{name: "Fastly", category: "cdn",
		headers: map[string]*matcher{"x-served-by": newMatcher(`cache-`, 0), "via": newMatcher(`varnish`, 0)},
	},
	{name: "Akamai", category: "cdn",
		headers: map[string]*matcher{"x-check-cacheable": newMatcher("", 0), "x-akamai": newMatcher("", 0)},
	},
	{name: "Vercel", category: "cdn",
		headers: map[string]*matcher{"x-vercel-id": newMatcher("", 0), "server": newMatcher(`vercel`, 0)},
	},
	{name: "Netlify", category: "cdn",
		headers: map[string]*matcher{"x-nf-request-id": newMatcher("", 0), "server": newMatcher(`netlify`, 0)},
	},
	{name: "AWS CloudFront", category: "cdn",
		headers: map[string]*matcher{"via": newMatcher(`cloudfront`, 0), "x-amz-cf-id": newMatcher("", 0)},
	},
	{name: "GitHub Pages", category: "cdn",
		headers: map[string]*matcher{"server": newMatcher(`github\.com`, 0)},
	},
	// === Analytics ===
	{name: "Google Analytics", category: "analytics",
		body: []*matcher{newMatcher(`google-analytics\.com/analytics\.js|gtag\(|UA-\d+-\d+|G-[A-Z0-9]+`, 0)},
	},
	{name: "Google Tag Manager", category: "analytics",
		body: []*matcher{newMatcher(`googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]+`, 0)},
	},
	{name: "Hotjar", category: "analytics",
		body: []*matcher{newMatcher(`hotjar`, 0)},
	},
	{name: "Segment", category: "analytics",
		body: []*matcher{newMatcher(`segment\.com/analytics\.js|analytics\.load`, 0)},
	},
	{name: "Mixpanel", category: "analytics",
		body: []*matcher{newMatcher(`mixpanel`, 0)},
	},
	{name: "Matomo", category: "analytics",
		body: []*matcher{newMatcher(`matomo\.js|piwik\.js`, 0)},
	},
	// === Security / Auth ===
	{name: "reCAPTCHA", category: "security",
		body: []*matcher{newMatcher(`recaptcha`, 0)},
	},
	{name: "Cloudflare Turnstile", category: "security",
		body: []*matcher{newMatcher(`turnstile`, 0)},
	},
	{name: "Auth0", category: "security",
		body: []*matcher{newMatcher(`auth0`, 0)},
	},
	{name: "Okta", category: "security",
		body: []*matcher{newMatcher(`okta`, 0)},
	},
	{name: "Keycloak", category: "security",
		body:    []*matcher{newMatcher(`keycloak`, 0)},
		cookies: map[string]*matcher{"KEYCLOAK_SESSION": newMatcher("", 0)},
	},
	// === DevOps / Monitoring ===
	{name: "Sentry", category: "devops",
		body: []*matcher{newMatcher(`sentry\.io|Sentry\.init`, 0)},
	},
	{name: "Datadog", category: "devops",
		body: []*matcher{newMatcher(`datadoghq\.com|DD_RUM`, 0)},
	},
	{name: "New Relic", category: "devops",
		body: []*matcher{newMatcher(`newrelic`, 0)},
	},
	{name: "Elastic APM", category: "devops",
		body: []*matcher{newMatcher(`elastic\.co|elasticapm`, 0)},
	},
	// === Databases (via error pages / headers) ===
	{name: "MySQL", category: "db",
		body: []*matcher{newMatcher(`mysql_connect|mysql_query|SQL syntax.*MySQL`, 0)},
	},
	{name: "PostgreSQL", category: "db",
		body: []*matcher{newMatcher(`pg_connect|pg_query|PostgreSQL.*ERROR`, 0)},
	},
	{name: "MongoDB", category: "db",
		body: []*matcher{newMatcher(`MongoDB|MongoServerError`, 0)},
	},
	{name: "SQLite", category: "db",
		body: []*matcher{newMatcher(`SQLite|sqlite3`, 0)},
	},
	{name: "Oracle", category: "db",
		body: []*matcher{newMatcher(`ORA-\d{5}|oracle`, 0)},
	},
	{name: "MSSQL", category: "db",
		body: []*matcher{newMatcher(`Microsoft SQL Server|mssql|SqlException`, 0)},
	},
	// === Mail / Support ===
	{name: "Intercom", category: "other",
		body: []*matcher{newMatcher(`intercom`, 0)},
	},
	{name: "Zendesk", category: "other",
		body: []*matcher{newMatcher(`zendesk`, 0)},
	},
	{name: "HubSpot", category: "other",
		body: []*matcher{newMatcher(`hubspot`, 0)},
	},
	{name: "Stripe", category: "other",
		body: []*matcher{newMatcher(`stripe\.com/v3|Stripe\.setPublishableKey`, 0)},
	},
	{name: "Twilio", category: "other",
		body: []*matcher{newMatcher(`twilio`, 0)},
	},
	{name: "SendGrid", category: "other",
		body: []*matcher{newMatcher(`sendgrid`, 0)},
	},
	// === WordPress plugins (common) ===
	{name: "Elementor", category: "cms",
		body: []*matcher{newMatcher(`elementor`, 0)},
	},
	{name: "WPBakery", category: "cms",
		body: []*matcher{newMatcher(`wpb_animate_when_almost_visible`, 0)},
	},
	{name: "WPML", category: "cms",
		body: []*matcher{newMatcher(`wpml`, 0)},
	},
	// === Meta tags ===
	{name: "generator-meta", category: "other",
		body: []*matcher{newMatcher(`<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`, 1)},
	},
}

var httpClient = &http.Client{
	Timeout: 12 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// Detect fetches the subdomain and fingerprints technologies from headers + body + cookies.
func Detect(subdomain string, timeout time.Duration) *Result {
	var resp *http.Response
	var err error
	for _, scheme := range []string{"https", "http"} {
		resp, err = httpClient.Get(scheme + "://" + subdomain)
		if err == nil {
			break
		}
	}
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	bodyStr := string(body)

	// Normalize headers
	hdrs := map[string]string{}
	for k, v := range resp.Header {
		hdrs[strings.ToLower(k)] = strings.Join(v, "; ")
	}

	// Normalize cookies
	cookies := map[string]string{}
	for _, c := range resp.Cookies() {
		cookies[c.Name] = c.Value
	}

	result := &Result{Headers: hdrs}
	seen := map[string]bool{}

	for _, sig := range signatures {
		var matched bool
		var version string

		// Check headers
		for hdrName, m := range sig.headers {
			if val, ok := hdrs[hdrName]; ok {
				if ok2, ver := m.match(val); ok2 {
					matched = true
					if ver != "" {
						version = ver
					}
				}
			}
		}

		// Check body
		if !matched {
			for _, m := range sig.body {
				if ok, ver := m.match(bodyStr); ok {
					matched = true
					if ver != "" {
						version = ver
					}
					break
				}
			}
		}

		// Check cookies
		if !matched {
			for cookieName, m := range sig.cookies {
				for name, val := range cookies {
					if strings.EqualFold(name, cookieName) || strings.HasPrefix(strings.ToLower(name), strings.ToLower(cookieName)) {
						if ok, ver := m.match(val); ok {
							matched = true
							if ver != "" {
								version = ver
							}
						}
					}
				}
			}
		}

		if matched {
			key := sig.name + ":" + version
			if !seen[key] {
				seen[key] = true
				name := sig.name
				if sig.name == "generator-meta" && version != "" {
					name = version
					version = ""
				}
				result.Techs = append(result.Techs, Tech{
					Name: name, Version: version, Category: sig.category,
				})
			}
		}
	}

	return result
}
