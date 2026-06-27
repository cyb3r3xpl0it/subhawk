package defaultcreds

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

type Result struct {
	URL      string
	Username string
	Password string
	Method   string // "basic" or "form"
}

type Credential struct {
	Username string
	Password string
}

var DefaultCreds = []Credential{
	{"admin", "admin"}, {"admin", "password"}, {"admin", "1234"},
	{"admin", "12345"}, {"admin", "123456"}, {"admin", "admin123"},
	{"admin", "password123"}, {"root", "root"}, {"root", "toor"},
	{"admin", ""}, {"administrator", "administrator"},
	{"user", "user"}, {"test", "test"}, {"guest", "guest"},
}

func newClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func tryBasicAuth(client *http.Client, panelURL, username, password string) bool {
	req, err := http.NewRequest("GET", panelURL, nil)
	if err != nil {
		return false
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set("Authorization", "Basic "+encoded)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; subhawk)")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return false
	}

	if resp.StatusCode == http.StatusOK {
		return true
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" && !isLoginRedirect(location, panelURL) {
			return true
		}
	}

	return false
}

func isLoginRedirect(location, originalURL string) bool {
	loc := strings.ToLower(location)
	loginKeywords := []string{"login", "signin", "sign-in", "auth", "logon"}
	for _, kw := range loginKeywords {
		if strings.Contains(loc, kw) {
			return true
		}
	}

	origParsed, err := url.Parse(originalURL)
	if err != nil {
		return false
	}
	locParsed, err := url.Parse(location)
	if err != nil {
		return false
	}

	if !locParsed.IsAbs() {
		return strings.EqualFold(origParsed.Path, locParsed.Path)
	}

	return strings.EqualFold(origParsed.Host+origParsed.Path, locParsed.Host+locParsed.Path)
}

type formInfo struct {
	action        string
	usernameField string
	passwordField string
}

func detectLoginForm(body string, baseURL string) *formInfo {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}

	var info *formInfo
	var findForm func(*html.Node) *formInfo

	findForm = func(n *html.Node) *formInfo {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "form") {
			fi := extractFormInfo(n, baseURL)
			if fi != nil {
				return fi
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if result := findForm(c); result != nil {
				return result
			}
		}
		return nil
	}

	info = findForm(doc)
	return info
}

func extractFormInfo(formNode *html.Node, baseURL string) *formInfo {
	fi := &formInfo{}

	for _, attr := range formNode.Attr {
		if strings.EqualFold(attr.Key, "action") {
			action := strings.TrimSpace(attr.Val)
			if action == "" {
				fi.action = baseURL
			} else if strings.HasPrefix(action, "http://") || strings.HasPrefix(action, "https://") {
				fi.action = action
			} else {
				parsed, err := url.Parse(baseURL)
				if err == nil {
					ref, err := url.Parse(action)
					if err == nil {
						fi.action = parsed.ResolveReference(ref).String()
					}
				}
			}
		}
	}

	if fi.action == "" {
		fi.action = baseURL
	}

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "input") {
			var inputType, inputName string
			for _, attr := range n.Attr {
				switch strings.ToLower(attr.Key) {
				case "type":
					inputType = strings.ToLower(attr.Val)
				case "name":
					inputName = attr.Val
				}
			}

			if inputType == "password" && fi.passwordField == "" {
				fi.passwordField = inputName
			} else if (inputType == "text" || inputType == "email" || inputType == "") && fi.usernameField == "" {
				nameLower := strings.ToLower(inputName)
				if strings.Contains(nameLower, "user") || strings.Contains(nameLower, "email") ||
					strings.Contains(nameLower, "login") || strings.Contains(nameLower, "name") ||
					strings.Contains(nameLower, "account") {
					fi.usernameField = inputName
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(formNode)

	if fi.usernameField == "" {
		var findFirstText func(*html.Node)
		findFirstText = func(n *html.Node) {
			if fi.usernameField != "" {
				return
			}
			if n.Type == html.ElementNode && strings.EqualFold(n.Data, "input") {
				var inputType, inputName string
				for _, attr := range n.Attr {
					switch strings.ToLower(attr.Key) {
					case "type":
						inputType = strings.ToLower(attr.Val)
					case "name":
						inputName = attr.Val
					}
				}
				if (inputType == "text" || inputType == "email" || inputType == "") && inputName != "" {
					fi.usernameField = inputName
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				findFirstText(c)
			}
		}
		findFirstText(formNode)
	}

	if fi.passwordField == "" {
		return nil
	}

	return fi
}

func tryFormAuth(client *http.Client, panelURL, username, password string) bool {
	req, err := http.NewRequest("GET", panelURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; subhawk)")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false
	}
	body := string(bodyBytes)

	fi := detectLoginForm(body, panelURL)
	if fi == nil {
		return false
	}

	formData := url.Values{}
	if fi.usernameField != "" {
		formData.Set(fi.usernameField, username)
	}
	if fi.passwordField != "" {
		formData.Set(fi.passwordField, password)
	}

	postReq, err := http.NewRequest("POST", fi.action, strings.NewReader(formData.Encode()))
	if err != nil {
		return false
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; subhawk)")
	postReq.Header.Set("Referer", panelURL)

	postResp, err := client.Do(postReq)
	if err != nil {
		return false
	}
	defer postResp.Body.Close()

	if postResp.StatusCode == http.StatusFound || postResp.StatusCode == http.StatusMovedPermanently ||
		postResp.StatusCode == http.StatusSeeOther || postResp.StatusCode == http.StatusTemporaryRedirect {
		location := postResp.Header.Get("Location")
		if location != "" && !isLoginRedirect(location, panelURL) {
			return true
		}
		if location != "" && isLoginRedirect(location, panelURL) {
			return false
		}
		return true
	}

	if postResp.StatusCode == http.StatusOK {
		respBodyBytes, err := io.ReadAll(io.LimitReader(postResp.Body, 1<<20))
		if err != nil {
			return false
		}
		respBody := strings.ToLower(string(respBodyBytes))
		failureKeywords := []string{"invalid", "incorrect", "failed", "wrong", "error", "denied", "unauthorized"}
		for _, kw := range failureKeywords {
			if strings.Contains(respBody, kw) {
				return false
			}
		}
		return true
	}

	return false
}

func hasBasicAuthChallenge(client *http.Client, panelURL string) bool {
	req, err := http.NewRequest("GET", panelURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; subhawk)")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if strings.Contains(strings.ToLower(wwwAuth), "basic") {
			return true
		}
	}
	return false
}

func hasLoginForm(client *http.Client, panelURL string) bool {
	req, err := http.NewRequest("GET", panelURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; subhawk)")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false
	}

	fi := detectLoginForm(string(bodyBytes), panelURL)
	return fi != nil
}

// Check tests an admin panel URL for default credentials.
// It tries HTTP Basic Auth and common form-based login patterns.
func Check(panelURL string, timeout time.Duration) []Result {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	client := newClient(timeout)
	var results []Result

	useBasic := hasBasicAuthChallenge(client, panelURL)
	useForm := !useBasic && hasLoginForm(client, panelURL)

	for _, cred := range DefaultCreds {
		if useBasic {
			if tryBasicAuth(client, panelURL, cred.Username, cred.Password) {
				results = append(results, Result{
					URL:      panelURL,
					Username: cred.Username,
					Password: cred.Password,
					Method:   "basic",
				})
				break
			}
		} else if useForm {
			if tryFormAuth(client, panelURL, cred.Username, cred.Password) {
				results = append(results, Result{
					URL:      panelURL,
					Username: cred.Username,
					Password: cred.Password,
					Method:   "form",
				})
				break
			}
		}
	}

	return results
}
