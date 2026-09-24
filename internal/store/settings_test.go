package store

import "testing"

// TestLoadSettings_DefaultsOnEmptyTable checks that an install that has never
// saved a setting gets exactly the spec's defaults (§9.4), not zero values —
// a fresh mon-server must poll every 60s and treat 3 consecutive failures as
// DOWN out of the box, before anyone has ever opened the admin UI.
func TestLoadSettings_DefaultsOnEmptyTable(t *testing.T) {
	s := openTestStore(t)

	got, err := s.LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	want := DefaultSettings()
	if *got != *want {
		t.Fatalf("LoadSettings() = %+v, want defaults %+v", got, want)
	}
}

// TestSettings_RoundTrip checks that SaveSettings followed by LoadSettings
// returns exactly what was saved, across every field including the string
// settings that have no default (panelUrl, monToken, ...).
func TestSettings_RoundTrip(t *testing.T) {
	s := openTestStore(t)

	want := &Settings{
		PanelURL: "https://panel.example:2053/base/",
		MonToken: "secret-token",
		RealHost: "real.example.com",
		PanelCA:  "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		TgToken:  "bot:token",
		TgChatID: "-100123456",

		DownAfter:          5,
		UpAfter:            1,
		FlapN:              6,
		FlapMin:            45,
		FlapHoldMin:        20,
		ClientOfflineAfter: 4,
		PanelDownAfter:     2,

		IntervalMs:         30000,
		BudgetMs:           15000,
		ConnectMs:          4000,
		TlsMs:              8000,
		HeadersMs:          9000,
		StartJitterMs:      2000,
		HeartbeatTimeoutMs: 7000,
	}

	if err := s.SaveSettings(want); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	got, err := s.LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if *got != *want {
		t.Fatalf("LoadSettings() after SaveSettings = %+v, want %+v", got, want)
	}
}

// TestSettings_PartialSaveKeepsOtherDefaults checks that saving once, then
// loading, still reports spec defaults for keys the caller never mentioned —
// LoadSettings must not confuse "an empty settings table" with "a table
// where only some keys are missing".
func TestSettings_PartialSaveKeepsOtherDefaults(t *testing.T) {
	s := openTestStore(t)

	first := DefaultSettings()
	first.PanelURL = "https://panel.example/"
	if err := s.SaveSettings(first); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	got, err := s.LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if got.PanelURL != "https://panel.example/" {
		t.Fatalf("PanelURL = %q, want saved value", got.PanelURL)
	}
	if got.DownAfter != DefaultSettings().DownAfter {
		t.Fatalf("DownAfter = %d, want default %d", got.DownAfter, DefaultSettings().DownAfter)
	}
}

// TestSaveSettings_Upserts checks that saving twice updates in place rather
// than erroring or duplicating rows — the admin UI's Save button is called
// repeatedly against the same keys for the life of the install.
func TestSaveSettings_Upserts(t *testing.T) {
	s := openTestStore(t)

	set := DefaultSettings()
	set.DownAfter = 3
	if err := s.SaveSettings(set); err != nil {
		t.Fatalf("first SaveSettings: %v", err)
	}
	set.DownAfter = 9
	if err := s.SaveSettings(set); err != nil {
		t.Fatalf("second SaveSettings: %v", err)
	}

	got, err := s.LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if got.DownAfter != 9 {
		t.Fatalf("DownAfter = %d, want 9 after second save", got.DownAfter)
	}

	var count int64
	if err := s.DB.Model(&Setting{}).Where("key = ?", settingDownAfter).Count(&count).Error; err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("row count for %s = %d, want 1 (upsert, not duplicate)", settingDownAfter, count)
	}
}
