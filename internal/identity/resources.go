package identity

import (
	"net/http"
	"net/url"
	"strings"
)

const (
	ResourceImage     = "image"
	ResourceStream    = "stream"
	ResourceSmartSTRM = "smartstrm"
)

// NormalizeImpersonatedResource converges image, playback stream, and smartstrm
// requests to the shapes used by the impersonated clients. It runs after the
// generic identity rewrite, which preserves authorization that those requests do not send.
func (m *Manager) NormalizeImpersonatedResource(u *url.URL, headers http.Header, profile string, kind string) {
	if u == nil {
		return
	}
	switch kind {
	case ResourceImage, ResourceStream, ResourceSmartSTRM:
	default:
		return
	}
	snap := Snapshot{Profile: NormalizeProfile(profile)}
	if m != nil {
		snap = m.Snapshot(profile)
	}
	model := GetProfile(snap.Profile).requests
	token := impersonatedResourceToken(u, headers)
	stripImpersonatedResourceHeaders(headers)
	q := u.Query()
	removeImpersonatedResourceQueryIdentity(q)
	switch kind {
	case ResourceImage:
		deleteNormalizedQueryKey(q, "deviceid")
		if model.userImageToken != "" && isUserImagePath(u) && token != "" {
			q.Set(model.userImageToken, token)
		}
	case ResourceStream:
		// Real clients request the stream URL issued by PlaybackInfo as-is. Keep its
		// token parameters, and replace DeviceId only when the URL already has one.
		// u still holds the original query here; q has had identity keys removed.
		deleteNormalizedQueryKey(q, "deviceid")
		if snap.DeviceID != "" && hasNonEmptyQueryKey(u.Query(), "deviceid") {
			q.Set("DeviceId", snap.DeviceID)
		}
		if value := firstQueryValueByNormalizedKey(u, "xembytoken"); value != "" {
			q.Set("X-Emby-Token", value)
		}
		// Only add api_key when the URL carries no token at all.
		if token != "" && !hasNonEmptyQueryKey(q, "apikey", "xembytoken") {
			q.Set("api_key", token)
		}
	case ResourceSmartSTRM:
		deleteNormalizedQueryKey(q, "deviceid")
		deleteNormalizedQueryKey(q, "devicename")
		if token != "" {
			q.Set("api_key", token)
		}
	}
	u.RawQuery = q.Encode()
}

func isUserImagePath(u *url.URL) bool {
	if u == nil {
		return false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i := 0; i+2 < len(parts); i++ {
		if strings.EqualFold(parts[i], "users") &&
			strings.TrimSpace(parts[i+1]) != "" &&
			!isUsersCollectionAction(parts[i+1]) &&
			strings.EqualFold(parts[i+2], "images") {
			return true
		}
	}
	return false
}

func impersonatedResourceToken(u *url.URL, headers http.Header) string {
	return firstSanitizedToken(
		firstHeaderValue(headers, "X-Emby-Token"),
		firstHeaderValue(headers, "X-MediaBrowser-Token"),
		firstHeaderValueByNormalizedKey(headers, "xembytoken"),
		firstHeaderValueByNormalizedKey(headers, "xmediabrowsertoken"),
		firstQueryValueByNormalizedKey(u, "xembytoken"),
		firstQueryValueByNormalizedKey(u, "xmediabrowsertoken"),
		firstQueryValueByNormalizedKey(u, "apikey"),
		authTokenFromURL(u),
		authTokenFromHeaders(headers),
	)
}

func stripImpersonatedResourceHeaders(headers http.Header) {
	if headers == nil {
		return
	}
	stripImpersonationHeaders(headers)
	for key := range cloneHeader(headers) {
		switch normalizeHeaderKey(key) {
		case "xembytoken", "xmediabrowsertoken":
			deleteHeaderKey(headers, key)
		}
	}
}

func removeImpersonatedResourceQueryIdentity(q url.Values) {
	for key, values := range q {
		if isQueryIdentityParam(normalizeHeaderKey(key), values) {
			q.Del(key)
		}
	}
}

func hasNonEmptyQueryKey(q url.Values, normalizedKeys ...string) bool {
	for key, values := range q {
		normalized := normalizeHeaderKey(key)
		for _, want := range normalizedKeys {
			if normalized != want {
				continue
			}
			for _, value := range values {
				if strings.TrimSpace(value) != "" {
					return true
				}
			}
		}
	}
	return false
}

func deleteNormalizedQueryKey(q url.Values, normalizedKey string) bool {
	changed := false
	for key := range q {
		if normalizeHeaderKey(key) == normalizedKey {
			q.Del(key)
			changed = true
		}
	}
	return changed
}
