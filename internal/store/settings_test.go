package store

import (
	"reflect"
	"sort"
	"testing"
)

// savedSettings is a fully populated Settings used by the round-trip tests.
func savedSettings() Settings {
	return Settings{
		PanelURL:           "https://panel.example.net/app",
		MonToken:           "mon-token",
		RealHost:           "203.0.113.10",
		TGToken:            "123:abc",
		TGChatID:           "-1001",
		DownAfter:          5,
		UpAfter:            4,
		FlapN:              6,
		FlapMin:            45,
		FlapHoldMin:        20,
		ClientOfflineAfter: 2,
		PanelDownAfter:     7,
		IntervalMs:         30000,
		BudgetMs:           15000,
		ConnectMs:          4000,
		TLSMs:              9000,
		HeadersMs:          8000,
		StartJitterMs:      2500,
		HeartbeatTimeoutMs: 7000,
	}
}

func TestSettingsDefaultsOnAnEmptyDatabase(t *testing.T) {
	s, _ := openTestStore(t)

	got, err := s.Settings()
	if err != nil {
		t.Fatalf("Settings: %v", err)
	}
	if want := DefaultSettings(); !reflect.DeepEqual(got, want) {
		t.Errorf("Settings on an empty database = %+v, want %+v", got, want)
	}

	// The documented defaults of spec §9.4, spelled out so a silent change
	// to DefaultSettings fails here.
	want := Settings{
		DownAfter: 3, UpAfter: 2, FlapN: 4, FlapMin: 30, FlapHoldMin: 15,
		ClientOfflineAfter: 3, PanelDownAfter: 3,
		IntervalMs: 60000, BudgetMs: 20000, ConnectMs: 5000, TLSMs: 10000,
		HeadersMs: 10000, StartJitterMs: 5000, HeartbeatTimeoutMs: 10000,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("defaults = %+v, want %+v", got, want)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	s, _ := openTestStore(t)

	want := savedSettings()
	if err := s.SaveSettings(want); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	got, err := s.Settings()
	if err != nil {
		t.Fatalf("Settings: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Settings after SaveSettings = %+v, want %+v", got, want)
	}

	// Saving again with one field changed replaces only that row's value.
	want.RealHost = "real.example.net"
	if err := s.SaveSettings(want); err != nil {
		t.Fatalf("SaveSettings (second): %v", err)
	}
	got, err = s.Settings()
	if err != nil {
		t.Fatalf("Settings: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Settings after the second save = %+v, want %+v", got, want)
	}
}

func TestSaveSettingsWritesEveryKey(t *testing.T) {
	s, _ := openTestStore(t)

	if err := s.SaveSettings(savedSettings()); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	stored, err := s.AllSettings()
	if err != nil {
		t.Fatalf("AllSettings: %v", err)
	}
	want := []string{
		KeyBudgetMs, KeyClientOfflineAfter, KeyConnectMs, KeyDownAfter,
		KeyFlapHoldMin, KeyFlapMin, KeyFlapN, KeyHeadersMs,
		KeyHeartbeatTimeoutMs, KeyIntervalMs, KeyMonToken, KeyPanelDownAfter,
		KeyPanelURL, KeyRealHost, KeyStartJitterMs, KeyTGChatID, KeyTGToken,
		KeyTLSMs, KeyUpAfter,
	}
	got := make([]string, 0, len(stored))
	for key := range stored {
		got = append(got, key)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stored keys:\n got %v\nwant %v", got, want)
	}
	if stored[KeyDownAfter] != "5" || stored[KeyPanelURL] != "https://panel.example.net/app" {
		t.Errorf("stored values are not the typed ones: %v", stored)
	}
}

func TestSettingsFallBackToDefaults(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  func(Settings) any
		got   func(Settings) any
	}{
		{
			name:  "blank number keeps the default",
			key:   KeyDownAfter,
			value: "",
			want:  func(d Settings) any { return d.DownAfter },
			got:   func(v Settings) any { return v.DownAfter },
		},
		{
			name:  "unparsable number keeps the default",
			key:   KeyIntervalMs,
			value: "soon",
			want:  func(d Settings) any { return d.IntervalMs },
			got:   func(v Settings) any { return v.IntervalMs },
		},
		{
			name:  "number with surrounding spaces is accepted",
			key:   KeyUpAfter,
			value: "  9 ",
			want:  func(Settings) any { return 9 },
			got:   func(v Settings) any { return v.UpAfter },
		},
		{
			name:  "blank string is the cleared value",
			key:   KeyPanelURL,
			value: "",
			want:  func(Settings) any { return "" },
			got:   func(v Settings) any { return v.PanelURL },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := openTestStore(t)
			if err := s.SetSetting(tc.key, tc.value); err != nil {
				t.Fatalf("SetSetting: %v", err)
			}
			got, err := s.Settings()
			if err != nil {
				t.Fatalf("Settings: %v", err)
			}
			if want := tc.want(DefaultSettings()); tc.got(got) != want {
				t.Errorf("%s = %v, want %v", tc.key, tc.got(got), want)
			}
		})
	}
}

func TestSettingsIgnoreUnknownKeys(t *testing.T) {
	s, _ := openTestStore(t)

	if err := s.SetSetting("someKeyFromTheFuture", "42"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	got, err := s.Settings()
	if err != nil {
		t.Fatalf("Settings: %v", err)
	}
	if want := DefaultSettings(); !reflect.DeepEqual(got, want) {
		t.Errorf("an unknown key changed the settings: %+v", got)
	}
}

func TestSettingKeyValueAPI(t *testing.T) {
	s, _ := openTestStore(t)

	value, ok, err := s.LookupSetting(KeyMonToken)
	if err != nil {
		t.Fatalf("LookupSetting: %v", err)
	}
	if ok || value != "" {
		t.Errorf("LookupSetting on a missing key = %q, %v, want \"\", false", value, ok)
	}
	if value, err := s.Setting(KeyMonToken); err != nil || value != "" {
		t.Errorf("Setting on a missing key = %q, %v, want \"\", nil", value, err)
	}

	if err := s.SetSetting(KeyMonToken, "first"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if err := s.SetSetting(KeyMonToken, "second"); err != nil {
		t.Fatalf("SetSetting (overwrite): %v", err)
	}
	value, ok, err = s.LookupSetting(KeyMonToken)
	if err != nil {
		t.Fatalf("LookupSetting: %v", err)
	}
	if !ok || value != "second" {
		t.Errorf("LookupSetting = %q, %v, want \"second\", true", value, ok)
	}

	if err := s.SetSettings(map[string]string{KeyRealHost: "203.0.113.10", KeyTGChatID: "-1001"}); err != nil {
		t.Fatalf("SetSettings: %v", err)
	}
	if err := s.SetSettings(nil); err != nil {
		t.Fatalf("SetSettings(nil): %v", err)
	}
	stored, err := s.AllSettings()
	if err != nil {
		t.Fatalf("AllSettings: %v", err)
	}
	if stored[KeyRealHost] != "203.0.113.10" || stored[KeyTGChatID] != "-1001" || stored[KeyMonToken] != "second" {
		t.Errorf("stored settings = %v", stored)
	}
}

func TestPanelStateRoundTrip(t *testing.T) {
	s, _ := openTestStore(t)

	got, err := s.PanelState()
	if err != nil {
		t.Fatalf("PanelState: %v", err)
	}
	if want := DefaultPanelState(); !reflect.DeepEqual(got, want) {
		t.Errorf("PanelState on an empty database = %+v, want %+v", got, want)
	}
	if got.Status != PanelStatusUnknown {
		t.Errorf("status before the first poll = %q, want %q", got.Status, PanelStatusUnknown)
	}

	want := PanelState{
		LastRevision:    "a1b2c3d4",
		OverrideEnabled: true,
		OverrideHost:    "front.example.net",
		ProbeSubID:      "sub-1",
		LastCheckedAt:   1757721300000,
		LastError:       "",
		Status:          PanelStatusUp,
	}
	if err := s.SavePanelState(want); err != nil {
		t.Fatalf("SavePanelState: %v", err)
	}
	got, err = s.PanelState()
	if err != nil {
		t.Fatalf("PanelState: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PanelState = %+v, want %+v", got, want)
	}

	// A failed poll clears the override and records the error.
	want = PanelState{LastRevision: "a1b2c3d4", LastCheckedAt: 1757721360000, LastError: "http_timeout", Status: PanelStatusDown}
	if err := s.SavePanelState(want); err != nil {
		t.Fatalf("SavePanelState: %v", err)
	}
	got, err = s.PanelState()
	if err != nil {
		t.Fatalf("PanelState: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PanelState after a failed poll = %+v, want %+v", got, want)
	}
}

func TestPanelStateFallsBackOnUnusableValues(t *testing.T) {
	s, _ := openTestStore(t)

	err := s.SetSettings(map[string]string{
		KeyPanelOverrideEnabled: "yesterday",
		KeyPanelLastCheckedAt:   "not-a-number",
		KeyPanelLastRevision:    "a1b2c3d4",
	})
	if err != nil {
		t.Fatalf("SetSettings: %v", err)
	}
	got, err := s.PanelState()
	if err != nil {
		t.Fatalf("PanelState: %v", err)
	}
	want := DefaultPanelState()
	want.LastRevision = "a1b2c3d4"
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PanelState = %+v, want %+v", got, want)
	}
}

func TestPanelStateKeysAreSeparateFromSettings(t *testing.T) {
	s, _ := openTestStore(t)

	if err := s.SavePanelState(PanelState{LastRevision: "rev", Status: PanelStatusUp}); err != nil {
		t.Fatalf("SavePanelState: %v", err)
	}
	settings, err := s.Settings()
	if err != nil {
		t.Fatalf("Settings: %v", err)
	}
	if want := DefaultSettings(); !reflect.DeepEqual(settings, want) {
		t.Errorf("the panel cache leaked into the settings: %+v", settings)
	}

	if err := s.SaveSettings(savedSettings()); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	state, err := s.PanelState()
	if err != nil {
		t.Fatalf("PanelState: %v", err)
	}
	if state.LastRevision != "rev" || state.Status != PanelStatusUp {
		t.Errorf("saving settings disturbed the panel cache: %+v", state)
	}
}
