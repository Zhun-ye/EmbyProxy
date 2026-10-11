package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"embyproxy/internal/storage"
)

const identityKey = "system:upstream_identity"
const DefaultProfile = "yamby"

type Snapshot struct {
	Profile       string `json:"profile"`
	Label         string `json:"label"`
	ClientName    string `json:"clientName"`
	ClientVersion string `json:"clientVersion"`
	DeviceName    string `json:"deviceName"`
	DeviceID      string `json:"deviceId"`
	ShortID       string `json:"shortId"`
	UserAgent     string `json:"userAgent"`
}

type deviceState struct {
	DeviceName string `json:"deviceName"`
	DeviceID   string `json:"deviceId"`
}

type persisted struct {
	ClientName    string                 `json:"clientName"`
	ClientVersion string                 `json:"clientVersion"`
	UserAgent     string                 `json:"userAgent"`
	Profiles      map[string]deviceState `json:"profiles"`
}

type Manager struct {
	store       *storage.Store
	mu          sync.Mutex
	profiles    map[string]deviceState
	initialized bool
}

func NewManager(store *storage.Store) *Manager {
	return &Manager{store: store, profiles: map[string]deviceState{}}
}

func (m *Manager) Init(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var saved persisted
	_, _ = m.store.KV().GetJSON(ctx, identityKey, &saved)
	m.profiles = normalizeSavedProfiles(saved.Profiles)
	m.initialized = true
	current := m.persistedLocked()
	if !samePersisted(saved, current) {
		return m.store.KV().Put(ctx, identityKey, current)
	}
	return nil
}

func (m *Manager) Snapshot(profile string) Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureLocked()
	return m.snapshotLocked(profile)
}

func (m *Manager) snapshotLocked(profile string) Snapshot {
	selected := GetProfile(profile)
	state := m.deviceStateLocked(selected.Key)
	shortID := state.DeviceID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	return Snapshot{
		Profile:       selected.Key,
		Label:         selected.Label,
		ClientName:    selected.ClientName,
		ClientVersion: selected.ClientVersion,
		DeviceName:    state.DeviceName,
		DeviceID:      state.DeviceID,
		ShortID:       shortID,
		UserAgent:     selected.UserAgent,
	}
}

func NormalizeProfile(value string) string {
	key := strings.ToLower(strings.TrimSpace(value))
	if _, ok := Profiles[key]; ok {
		return key
	}
	return DefaultProfile
}

func GetProfile(value string) Profile {
	return Profiles[NormalizeProfile(value)]
}

func ProfileKeys() []string {
	seen := map[string]bool{}
	keys := make([]string, 0, len(Profiles))
	for _, key := range ProfileOrder {
		if _, ok := Profiles[key]; ok && !seen[key] {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	extra := make([]string, 0, len(Profiles)-len(keys))
	for key := range Profiles {
		if !seen[key] {
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	return append(keys, extra...)
}

func (m *Manager) persistedLocked() persisted {
	current := m.snapshotLocked(DefaultProfile)
	profiles := map[string]deviceState{}
	for key := range Profiles {
		profiles[key] = m.deviceStateLocked(key)
	}
	return persisted{
		ClientName:    current.ClientName,
		ClientVersion: current.ClientVersion,
		UserAgent:     current.UserAgent,
		Profiles:      profiles,
	}
}

func (m *Manager) ensureLocked() {
	if m.initialized && m.profiles != nil {
		return
	}
	m.profiles = normalizeSavedProfiles(m.profiles)
	m.initialized = true
}

func (m *Manager) deviceStateLocked(profile string) deviceState {
	selected := GetProfile(profile)
	if m.profiles == nil {
		m.profiles = map[string]deviceState{}
	}
	state := normalizeDeviceState(selected, m.profiles[selected.Key])
	m.profiles[selected.Key] = state
	return state
}

func normalizeSavedProfiles(saved map[string]deviceState) map[string]deviceState {
	out := map[string]deviceState{}
	for key := range Profiles {
		out[key] = normalizeDeviceState(Profiles[key], saved[key])
	}
	return out
}

func normalizeDeviceState(profile Profile, saved deviceState) deviceState {
	name := strings.TrimSpace(profile.DeviceName)
	if name == "" {
		name = strings.TrimSpace(saved.DeviceName)
	}
	if name == "" {
		name = createHillsWindowsDeviceName()
	}
	deviceID := strings.ToLower(strings.TrimSpace(saved.DeviceID))
	if !validDeviceID(profile, deviceID) {
		deviceID = randomDeviceID(profile)
	}
	return deviceState{DeviceName: name, DeviceID: deviceID}
}

func samePersisted(a, b persisted) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func isHexLength(value string, length int) bool {
	if length <= 0 {
		length = 32
	}
	if len(value) != length {
		return false
	}
	for _, ch := range value {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
			continue
		}
		return false
	}
	return true
}

func validDeviceID(profile Profile, value string) bool {
	switch strings.ToLower(strings.TrimSpace(profile.DeviceIDFormat)) {
	case "uuid":
		return isUUID(value)
	default:
		return isHexLength(value, profile.DeviceIDLength)
	}
}

func randomDeviceID(profile Profile) string {
	switch strings.ToLower(strings.TrimSpace(profile.DeviceIDFormat)) {
	case "uuid":
		return randomUUID()
	default:
		return randomHex(profile.DeviceIDLength)
	}
}

func randomHex(length int) string {
	if length <= 0 {
		length = 32
	}
	buf := make([]byte, (length+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", length)
	}
	return hex.EncodeToString(buf)[:length]
}

func isUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, ch := range value {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
				continue
			}
			return false
		}
	}
	return true
}

func randomUUID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	hexed := hex.EncodeToString(buf)
	return hexed[:8] + "-" + hexed[8:12] + "-" + hexed[12:16] + "-" + hexed[16:20] + "-" + hexed[20:]
}

func createHillsWindowsDeviceName() string {
	return "DESKTOP-" + strings.ToUpper(randomHex(6))
}
