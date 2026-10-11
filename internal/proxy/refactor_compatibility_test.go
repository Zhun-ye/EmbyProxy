package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/storage"
)

func TestRefactorPreservesImpersonatedLoginCompatibility(t *testing.T) {
	const path = "/Users/AuthenticateByName"
	const body = `{"Username":"person","Password":"legacy-hash","Pw":"plaintext"}`
	for _, profile := range identity.ProfileOrder {
		t.Run(profile, func(t *testing.T) {
			node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: profile}
			h := newProxyTestHandler(t, node)
			h.ids = identity.NewManager(nil)
			var paths, origins []string
			h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				paths = append(paths, req.URL.Path)
				origins = append(origins, req.Header.Get("Origin"))
				raw, err := io.ReadAll(req.Body)
				if err != nil || string(raw) != body {
					t.Fatalf("login body = %q, error = %v; want unchanged body", raw, err)
				}
				if req.Header.Get("Content-Type") != "application/json;charset=utf-8" || req.Header.Get("X-Requested-With") != "XMLHttpRequest" {
					t.Fatalf("login compatibility headers changed: %v", req.Header)
				}
				if req.Header.Get("X-Emby-Token") != "source-token" {
					t.Fatalf("login token = %q, want existing source token", req.Header.Get("X-Emby-Token"))
				}
				if len(paths) < 3 {
					return textResponse(http.StatusNotFound, "retry", nil), nil
				}
				return textResponse(http.StatusOK, `{"AccessToken":"new-token"}`, http.Header{"Content-Type": {"application/json"}}), nil
			})}
			req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node"+path, strings.NewReader(body))
			req.Header.Set("Content-Type", "text/plain")
			req.Header.Set("X-Emby-Token", "source-token")
			req.Header.Set("X-Emby-Authorization", `Emby Client="Source",Device="PC",DeviceId="source-device",Version="1"`)
			res, err := h.handleOneTarget(context.Background(), req, node, parsedRoute{Name: "node", Path: path}, []byte(body), config.ProxyEnv{})
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK || !reflect.DeepEqual(paths, []string{"/emby" + path, "/emby" + path, path}) || !reflect.DeepEqual(origins, []string{"https://proxy.example", "", "https://proxy.example"}) {
				t.Fatalf("login compatibility changed: status=%d, paths=%v, origins=%v", res.StatusCode, paths, origins)
			}
		})
	}
}

func TestRefactorPreservesImpersonated403Retries(t *testing.T) {
	for _, profile := range identity.ProfileOrder {
		for _, image := range []bool{false, true} {
			kind, path := "api", "/Users/account/Views"
			wantOrigins := []string{"https://source.example", "", "https://upstream.example", "https://upstream.example"}
			if image {
				kind, path = "image", "/Items/item/Images/Primary"
				wantOrigins = []string{"", "", "https://upstream.example"}
			}
			t.Run(profile+"/"+kind, func(t *testing.T) {
				node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: profile}
				h := newProxyTestHandler(t, node)
				h.ids = identity.NewManager(nil)
				var origins []string
				client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					origins = append(origins, req.Header.Get("Origin"))
					if len(origins) < len(wantOrigins) {
						return textResponse(http.StatusForbidden, "retry", nil), nil
					}
					return textResponse(http.StatusOK, "ok", nil), nil
				})}
				h.noRedirectClient, h.imageFollowClient = client, client
				req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node"+path, nil)
				req.Header.Set("Origin", "https://source.example")
				res, err := h.handleOneTarget(context.Background(), req, node, parsedRoute{Name: "node", Path: path}, nil, config.ProxyEnv{})
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				if res.StatusCode != http.StatusOK || !reflect.DeepEqual(origins, wantOrigins) {
					t.Fatalf("403 compatibility changed: status=%d, origins=%v, want %v", res.StatusCode, origins, wantOrigins)
				}
			})
		}
	}
}

func TestRefactorPreservesImpersonatedCapyPathHandling(t *testing.T) {
	for _, profile := range identity.ProfileOrder {
		t.Run(profile, func(t *testing.T) {
			node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: profile}
			h := newProxyTestHandler(t, node)
			h.ids = identity.NewManager(nil)
			calls := 0
			h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Path != "/Users/account/Views" {
					t.Fatalf("configured Capy path handling changed: %s", req.URL.Path)
				}
				return textResponse(http.StatusOK, "ok", nil), nil
			})}
			const path = "/emby/Users/account/Views"
			req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node"+path, nil)
			req.Header.Set("User-Agent", "CapyPlayer/1.0")
			res, err := h.handleOneTarget(context.Background(), req, node, parsedRoute{Name: "node", Path: path}, nil, config.ProxyEnv{CapyStripEmby: "1"})
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK || calls != 1 {
				t.Fatalf("status=%d, calls=%d", res.StatusCode, calls)
			}
		})
	}
}

func TestRefactorPreservesImpersonatedImageWriteRouting(t *testing.T) {
	for _, profile := range identity.ProfileOrder {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			t.Run(profile+"/"+method, func(t *testing.T) {
				node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: profile}
				h := newProxyTestHandler(t, node)
				h.ids = identity.NewManager(nil)
				h.noRedirectClient = failRoundTripClient(t, "image write switched to the general API client")
				calls := 0
				h.imageFollowClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					raw, err := io.ReadAll(req.Body)
					if err != nil || string(raw) != "image data" || req.Method != method {
						t.Fatalf("image write changed: method=%s, body=%q, error=%v", req.Method, raw, err)
					}
					return textResponse(http.StatusOK, "ok", nil), nil
				})}
				const path = "/Items/item/Images/Primary"
				req := httptest.NewRequest(method, "https://proxy.example/node"+path, strings.NewReader("image data"))
				res, err := h.handleOneTarget(context.Background(), req, node, parsedRoute{Name: "node", Path: path}, []byte("image data"), config.ProxyEnv{})
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				if res.StatusCode != http.StatusOK || calls != 1 {
					t.Fatalf("status=%d, calls=%d", res.StatusCode, calls)
				}
			})
		}
	}
}
