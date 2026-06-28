package apidiscover

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type APIEndpoint struct {
	URL     string
	Type    string // "graphql", "swagger", "openapi", "grpc", "websocket"
	Details string
}

type Result struct {
	Endpoints    []APIEndpoint
	HasGraphQL   bool
	HasSwagger   bool
	HasGRPC      bool
	HasWebSocket bool
}

var graphqlPaths = []string{
	"/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql",
	"/query", "/api/query", "/graphiql", "/playground",
}

var swaggerPaths = []string{
	"/swagger.json", "/swagger.yaml", "/swagger-ui.html",
	"/api-docs", "/api-docs.json", "/openapi.json", "/openapi.yaml",
	"/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
	"/docs/api.json", "/redoc", "/api/swagger",
}

const graphqlQuery = `{"query":"{__schema{types{name}}}"}`

func newClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

func resolveBase(subdomain string, client *http.Client) string {
	for _, scheme := range []string{"https", "http"} {
		resp, err := client.Get(scheme + "://" + subdomain)
		if err == nil {
			resp.Body.Close()
			return scheme + "://" + subdomain
		}
	}
	return ""
}

func Discover(subdomain string, timeout time.Duration) *Result {
	client := newClient(timeout)
	base := resolveBase(subdomain, client)
	if base == "" {
		return nil
	}

	result := &Result{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, p := range graphqlPaths {
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()
			url := base + path
			req, err := http.NewRequest("POST", url, strings.NewReader(graphqlQuery))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil || resp.StatusCode == 404 || resp.StatusCode == 405 {
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			if strings.Contains(string(body), "__schema") || strings.Contains(string(body), "\"data\"") {
				mu.Lock()
				if !result.HasGraphQL {
					result.HasGraphQL = true
					result.Endpoints = append(result.Endpoints, APIEndpoint{
						URL: url, Type: "graphql", Details: "introspection enabled",
					})
				}
				mu.Unlock()
			}
		}(p)
	}

	for _, p := range swaggerPaths {
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()
			url := base + path
			resp, err := client.Get(url)
			if err != nil || resp.StatusCode == 404 || resp.StatusCode >= 500 {
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			bodyStr := string(body)
			if !strings.Contains(bodyStr, "swagger") && !strings.Contains(bodyStr, "openapi") &&
				!strings.Contains(bodyStr, "\"paths\"") && resp.StatusCode != 200 {
				return
			}
			var spec map[string]interface{}
			details := fmt.Sprintf("HTTP %d", resp.StatusCode)
			if json.Unmarshal(body, &spec) == nil {
				if v, ok := spec["openapi"].(string); ok {
					details = "OpenAPI " + v
				} else if v, ok := spec["swagger"].(string); ok {
					details = "Swagger " + v
				}
			}
			apiType := "swagger"
			if strings.Contains(bodyStr, "openapi") {
				apiType = "openapi"
			}
			mu.Lock()
			result.HasSwagger = true
			result.Endpoints = append(result.Endpoints, APIEndpoint{
				URL: url, Type: apiType, Details: details,
			})
			mu.Unlock()
		}(p)
	}

	wg.Add(1)
	sem <- struct{}{}
	go func() {
		defer wg.Done()
		defer func() { <-sem }()
		for _, wsPath := range []string{"/ws", "/websocket", "/socket", "/socket.io", "/ws/v1"} {
			url := base + wsPath
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == 101 || strings.Contains(resp.Header.Get("Upgrade"), "websocket") {
				mu.Lock()
				result.HasWebSocket = true
				result.Endpoints = append(result.Endpoints, APIEndpoint{
					URL: url, Type: "websocket", Details: fmt.Sprintf("HTTP %d", resp.StatusCode),
				})
				mu.Unlock()
				break
			}
		}
	}()

	wg.Add(1)
	sem <- struct{}{}
	go func() {
		defer wg.Done()
		defer func() { <-sem }()
		grpcBase := strings.Replace(base, "http://", "https://", 1)
		req, _ := http.NewRequest("POST", grpcBase+"/grpc.health.v1.Health/Check",
			strings.NewReader("\x00\x00\x00\x00\x00"))
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		resp.Body.Close()
		if strings.Contains(resp.Header.Get("Content-Type"), "application/grpc") ||
			resp.Header.Get("grpc-status") != "" {
			mu.Lock()
			result.HasGRPC = true
			result.Endpoints = append(result.Endpoints, APIEndpoint{
				URL: grpcBase, Type: "grpc", Details: "gRPC service detected",
			})
			mu.Unlock()
		}
	}()

	wg.Wait()
	return result
}
