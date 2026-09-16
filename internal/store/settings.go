package store

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Keys of the settings the administrator edits in the admin UI (spec §9.4).
// Anything not listed here is not a user setting.
const (
	KeyPanelURL           = "panelUrl"
	KeyMonToken           = "monToken"
	KeyRealHost           = "realHost"
	KeyTGToken            = "tgToken"
	KeyTGChatID           = "tgChatId"
	KeyDownAfter          = "downAfter"
	KeyUpAfter            = "upAfter"
	KeyFlapN              = "flapN"
	KeyFlapMin            = "flapMin"
	KeyFlapHoldMin        = "flapHoldMin"
	KeyClientOfflineAfter = "clientOfflineAfter"
	KeyPanelDownAfter     = "panelDownAfter"
	KeyIntervalMs         = "intervalMs"
	KeyBudgetMs           = "budgetMs"
	KeyConnectMs          = "connectMs"
	KeyTLSMs              = "tlsMs"
	KeyHeadersMs          = "headersMs"
	KeyStartJitterMs      = "startJitterMs"
	KeyHeartbeatTimeoutMs = "heartbeatTimeoutMs"
)

// Keys of the panel runtime cache. These are **not** user settings: mon-server
// writes them itself from the panel poll (spec §4) and the admin UI only reads
// them back for the Settings status line (spec §9.4). They share the settings
// table because they are the same kind of small singleton state.
const (
	KeyPanelLastRevision    = "panelLastRevision"
	KeyPanelOverrideEnabled = "panelOverrideEnabled"
	KeyPanelOverrideHost    = "panelOverrideHost"
	KeyPanelProbeSubID      = "panelProbeSubId"
	KeyPanelLastCheckedAt   = "panelLastCheckedAt"
	KeyPanelLastError       = "panelLastError"
	KeyPanelStatus          = "panelStatus"
)

// Settings is the typed view of the settings table (spec §9.4). Zero values
// are never meaningful: read it through Store.Settings, which fills in the
// defaults of DefaultSettings.
type Settings struct {
	// Real server tab.
	PanelURL string // base URL of the panel, including its webBasePath
	MonToken string // bearer token for the panel contract
	RealHost string // address used for path "direct"

	// Telegram tab.
	TGToken  string
	TGChatID string

	// Thresholds tab (spec §7.2, §7.3, §4.1).
	DownAfter          int // consecutive failures before DOWN
	UpAfter            int // consecutive successes before UP
	FlapN              int // transitions within FlapMin that mean FLAPPING
	FlapMin            int // flapping window, minutes
	FlapHoldMin        int // quiet period before leaving FLAPPING, minutes
	ClientOfflineAfter int // missed heartbeats before a mon-client is OFFLINE
	PanelDownAfter     int // consecutive panel failures before PANEL_DOWN

	// Probe tab: the probe parameters handed to mon-clients (spec §5).
	IntervalMs         int
	BudgetMs           int
	ConnectMs          int
	TLSMs              int
	HeadersMs          int
	StartJitterMs      int
	HeartbeatTimeoutMs int
}

// DefaultSettings returns the settings of a fresh installation (spec §9.4).
func DefaultSettings() Settings {
	return Settings{
		DownAfter:          3,
		UpAfter:            2,
		FlapN:              4,
		FlapMin:            30,
		FlapHoldMin:        15,
		ClientOfflineAfter: 3,
		PanelDownAfter:     3,
		IntervalMs:         60000,
		BudgetMs:           20000,
		ConnectMs:          5000,
		TLSMs:              10000,
		HeadersMs:          10000,
		StartJitterMs:      5000,
		HeartbeatTimeoutMs: 10000,
	}
}

// fields binds every settings key to its field. It is the single place that
// knows the mapping: Settings and SaveSettings both walk it.
func (v *Settings) fields() []kvField {
	return []kvField{
		{key: KeyPanelURL, str: &v.PanelURL},
		{key: KeyMonToken, str: &v.MonToken},
		{key: KeyRealHost, str: &v.RealHost},
		{key: KeyTGToken, str: &v.TGToken},
		{key: KeyTGChatID, str: &v.TGChatID},
		{key: KeyDownAfter, num: &v.DownAfter},
		{key: KeyUpAfter, num: &v.UpAfter},
		{key: KeyFlapN, num: &v.FlapN},
		{key: KeyFlapMin, num: &v.FlapMin},
		{key: KeyFlapHoldMin, num: &v.FlapHoldMin},
		{key: KeyClientOfflineAfter, num: &v.ClientOfflineAfter},
		{key: KeyPanelDownAfter, num: &v.PanelDownAfter},
		{key: KeyIntervalMs, num: &v.IntervalMs},
		{key: KeyBudgetMs, num: &v.BudgetMs},
		{key: KeyConnectMs, num: &v.ConnectMs},
		{key: KeyTLSMs, num: &v.TLSMs},
		{key: KeyHeadersMs, num: &v.HeadersMs},
		{key: KeyStartJitterMs, num: &v.StartJitterMs},
		{key: KeyHeartbeatTimeoutMs, num: &v.HeartbeatTimeoutMs},
	}
}

// PanelState is mon-server's own cache of the last panel poll (spec §4), shown
// read-only in the Settings status line (spec §9.4). It is not user
// configuration: only the panel poll writes it, and losing it costs one poll.
type PanelState struct {
	// LastRevision is the panel revision seen in the last GET /state; a
	// different one triggers a reread of /probe/configs.
	LastRevision string
	// OverrideEnabled and OverrideHost mirror the panel's host override, the
	// proxy front address used for path "proxy".
	OverrideEnabled bool
	OverrideHost    string
	// ProbeSubID is the probe account subscription id from the panel.
	ProbeSubID string
	// LastCheckedAt is ms UTC of the last completed poll.
	LastCheckedAt int64
	// LastError is the last poll failure, empty after a success.
	LastError string
	// Status is PanelStatusUp, PanelStatusDown or PanelStatusUnknown before
	// the first poll.
	Status string
}

// DefaultPanelState is the cache of a mon-server that has not polled yet.
func DefaultPanelState() PanelState { return PanelState{Status: PanelStatusUnknown} }

// fields binds every panel cache key to its field.
func (v *PanelState) fields() []kvField {
	return []kvField{
		{key: KeyPanelLastRevision, str: &v.LastRevision},
		{key: KeyPanelOverrideEnabled, flag: &v.OverrideEnabled},
		{key: KeyPanelOverrideHost, str: &v.OverrideHost},
		{key: KeyPanelProbeSubID, str: &v.ProbeSubID},
		{key: KeyPanelLastCheckedAt, num64: &v.LastCheckedAt},
		{key: KeyPanelLastError, str: &v.LastError},
		{key: KeyPanelStatus, str: &v.Status},
	}
}

// Settings returns the stored settings with defaults filled in. A value that
// is missing, blank or unusable keeps its default instead of failing the read:
// a typo in one row must not stop the poll loop.
func (s *Store) Settings() (Settings, error) {
	v := DefaultSettings()
	if err := s.loadFields(v.fields()); err != nil {
		return Settings{}, err
	}
	return v, nil
}

// SaveSettings writes every settings key in one transaction.
func (s *Store) SaveSettings(v Settings) error {
	return s.SetSettings(fieldValues(v.fields()))
}

// PanelState returns the cached panel poll state with defaults filled in.
func (s *Store) PanelState() (PanelState, error) {
	v := DefaultPanelState()
	if err := s.loadFields(v.fields()); err != nil {
		return PanelState{}, err
	}
	return v, nil
}

// SavePanelState writes the panel cache in one transaction.
func (s *Store) SavePanelState(v PanelState) error {
	return s.SetSettings(fieldValues(v.fields()))
}

// Setting returns the value stored under key, or "" when the key is absent.
// Callers that must tell "absent" from "blank" use LookupSetting.
func (s *Store) Setting(key string) (string, error) {
	value, _, err := s.LookupSetting(key)
	return value, err
}

// LookupSetting returns the value stored under key and whether the row exists.
func (s *Store) LookupSetting(key string) (string, bool, error) {
	var row Setting
	err := s.db.Where("key = ?", key).Take(&row).Error
	switch {
	case err == nil:
		return row.Value, true, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return "", false, nil
	default:
		return "", false, fmt.Errorf("store: read setting %q: %w", key, err)
	}
}

// SetSetting writes one key, inserting or replacing it.
func (s *Store) SetSetting(key, value string) error {
	return s.SetSettings(map[string]string{key: value})
}

// SetSettings writes every key of values in a single transaction, so a partly
// applied Save is never visible.
func (s *Store) SetSettings(values map[string]string) error {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	rows := make([]Setting, 0, len(keys))
	for _, key := range keys {
		rows = append(rows, Setting{Key: key, Value: values[key]})
	}
	err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value"}),
	}).Create(&rows).Error
	if err != nil {
		return fmt.Errorf("store: write settings: %w", err)
	}
	return nil
}

// AllSettings returns every row of the settings table, panel cache included.
func (s *Store) AllSettings() (map[string]string, error) {
	var rows []Setting
	if err := s.db.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("store: read settings: %w", err)
	}
	values := make(map[string]string, len(rows))
	for _, row := range rows {
		values[row.Key] = row.Value
	}
	return values, nil
}

// kvField binds one settings key to one typed field. Exactly one pointer is
// set.
type kvField struct {
	key   string
	str   *string
	num   *int
	num64 *int64
	flag  *bool
}

// format renders the field as it is stored.
func (f kvField) format() string {
	switch {
	case f.str != nil:
		return *f.str
	case f.num != nil:
		return strconv.Itoa(*f.num)
	case f.num64 != nil:
		return strconv.FormatInt(*f.num64, 10)
	case f.flag != nil:
		return strconv.FormatBool(*f.flag)
	default:
		return ""
	}
}

// parse assigns raw to the field, reporting an error when raw is unusable so
// that the caller can keep the default.
func (f kvField) parse(raw string) error {
	switch {
	case f.str != nil:
		*f.str = raw
		return nil
	case f.num != nil:
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return err
		}
		*f.num = n
		return nil
	case f.num64 != nil:
		n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			return err
		}
		*f.num64 = n
		return nil
	case f.flag != nil:
		b, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return err
		}
		*f.flag = b
		return nil
	default:
		return fmt.Errorf("no field bound")
	}
}

// loadFields reads the settings table once and applies it to fields, leaving
// the default in place wherever the stored value cannot be used.
func (s *Store) loadFields(fields []kvField) error {
	stored, err := s.AllSettings()
	if err != nil {
		return err
	}
	for _, f := range fields {
		raw, ok := stored[f.key]
		if !ok {
			continue
		}
		if err := f.parse(raw); err != nil {
			s.log.Warn("unusable stored setting, keeping the default", "key", f.key, "value", raw, "error", err)
		}
	}
	return nil
}

// fieldValues renders fields as the map SetSettings writes.
func fieldValues(fields []kvField) map[string]string {
	values := make(map[string]string, len(fields))
	for _, f := range fields {
		values[f.key] = f.format()
	}
	return values
}
