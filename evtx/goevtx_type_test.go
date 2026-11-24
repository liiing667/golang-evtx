package evtx_test

import (
	"regexp"
	"testing"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
)

func TestTypedValueAccessors(t *testing.T) {
	m := evtx.GoEvtxMap{
		"bool":   true,
		"false":  false,
		"string": "true",
		"int":    int64(-42),
		"uint":   uint64(42),
		"int32":  int32(-7),
		"uint32": uint32(7),
		"hex":    "0x10",
		"nested": map[string]interface{}{"value": int32(7)},
	}

	boolPath := evtx.Path("bool")
	b, err := m.GetBool(&boolPath)
	if err != nil || !b {
		t.Fatalf("native bool access failed: %v", err)
	}
	stringPath := evtx.Path("string")
	if b, err := m.GetBool(&stringPath); err != nil || !b {
		t.Fatalf("string bool access failed: %v", err)
	}
	intPath := evtx.Path("int")
	if _, err := m.GetBool(&intPath); err == nil {
		t.Fatal("integer was accepted as bool")
	}
	falsePath := evtx.Path("false")
	if b, err := m.GetBool(&falsePath); err != nil || b {
		t.Fatalf("native false bool access failed: value=%v err=%v", b, err)
	}

	i, err := m.GetInt(&intPath)
	if err != nil || i != -42 {
		t.Fatalf("native int access failed: %v", err)
	}
	if _, err := m.GetInt(&boolPath); err == nil {
		t.Fatal("bool was accepted as int")
	}
	hexPath := evtx.Path("hex")
	if got, err := m.GetInt(&hexPath); err != nil || got != 16 {
		t.Fatalf("legal integer string access failed: got=%d err=%v", got, err)
	}

	uintPath := evtx.Path("uint")
	u, err := m.GetUint(&uintPath)
	if err != nil || u != 42 {
		t.Fatalf("native uint access failed: %v", err)
	}
	int32Path := evtx.Path("int32")
	if got, err := m.GetInt(&int32Path); err != nil || got != -7 {
		t.Fatalf("native int32 access failed: got=%d err=%v", got, err)
	}
	uint32Path := evtx.Path("uint32")
	if got, err := m.GetUint(&uint32Path); err != nil || got != 7 {
		t.Fatalf("native uint32 access failed: got=%d err=%v", got, err)
	}

	nested := evtx.Path("nested/value")
	got, err := m.Get(&nested)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := (*got).(int32); !ok {
		t.Fatalf("nested value type not preserved: %T", *got)
	}
	genericPath := evtx.Path("nested")
	if _, err := m.GetMap(&genericPath); err != nil {
		t.Fatalf("GetMap does not support generic maps: %v", err)
	}
}

func TestMissingValueSemantics(t *testing.T) {
	m := evtx.GoEvtxMap{"present": true}
	path := evtx.Path("missing")

	zeroMap := evtx.GoEvtxMap{"zero": int64(0), "false": false}
	zeroPath := evtx.Path("zero")
	if got, err := zeroMap.GetInt(&zeroPath); err != nil || got != 0 {
		t.Fatalf("zero integer was not distinguished from missing: got=%d err=%v", got, err)
	}
	falsePath := evtx.Path("false")
	if got, err := zeroMap.GetBool(&falsePath); err != nil || got {
		t.Fatalf("false bool was not distinguished from missing: got=%v err=%v", got, err)
	}

	if _, err := m.Get(&path); !isNotFound(err) {
		t.Fatalf("Get did not preserve missing error: %T", err)
	}
	if _, err := m.GetMap(&path); !isNotFound(err) {
		t.Fatalf("GetMap did not preserve missing error: %T", err)
	}
	if _, err := m.GetMapWhere(&path, true); !isNotFound(err) {
		t.Fatalf("GetMapWhere did not preserve missing error: %T", err)
	}
	if m.Equal(&path, true) || m.AnyEqual(&path, []interface{}{true}) {
		t.Fatal("missing value matched equality filter")
	}
	if m.RegexMatch(&path, regexp.MustCompile(".*")) {
		t.Fatal("missing value matched regex filter")
	}

	at := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if m.Between(at, at.Add(time.Second)) {
		t.Fatal("missing timestamp matched Between filter")
	}
}

func TestTypePreservingFilters(t *testing.T) {
	m := evtx.GoEvtxMap{
		"bool":       true,
		"string":     "true",
		"int":        int64(1),
		"uint":       uint64(1),
		"pattern":    "event-123",
		"child":      evtx.GoEvtxMap{"Name": "Target", "Value": int64(7)},
		"otherChild": evtx.GoEvtxMap{"Name": "Other", "Value": "x"},
	}

	if !m.Equal(ptrPath("bool"), true) || m.Equal(ptrPath("bool"), "true") || m.Equal(ptrPath("bool"), int64(1)) {
		t.Fatal("Equal did not preserve bool value domain")
	}
	if !m.Equal(ptrPath("int"), int64(1)) || m.Equal(ptrPath("int"), uint64(1)) || m.Equal(ptrPath("int"), "1") {
		t.Fatal("Equal did not preserve integer value domain")
	}
	if m.AnyEqual(ptrPath("bool"), []interface{}{"true", int64(1)}) {
		t.Fatal("AnyEqual crossed bool value domains")
	}

	if !m.RegexMatch(ptrPath("pattern"), regexp.MustCompile(`event-\d+`)) {
		t.Fatal("string regex filter stopped matching")
	}
	if m.RegexMatch(ptrPath("bool"), regexp.MustCompile("true")) {
		t.Fatal("regex filter matched a bool")
	}
	if m.RegexMatch(ptrPath("int"), regexp.MustCompile("1")) {
		t.Fatal("regex filter matched an integer")
	}

	path := evtx.Path("child/Name")
	gotMap, err := m.GetMapWhere(&path, "Target")
	if err != nil {
		t.Fatal(err)
	}
	valuePath := evtx.Path("Value")
	value, err := gotMap.Get(&valuePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := (*value).(int64); !ok {
		t.Fatalf("GetMapWhere did not preserve value type: %T", *value)
	}

	missing := evtx.Path("otherChild/Name")
	if _, err := m.GetMapWhere(&missing, "Target"); !isNotFound(err) {
		t.Fatalf("non-matching GetMapWhere returned unexpected error: %T", err)
	}

	scalar := evtx.Path("int")
	if _, err := m.GetMapWhere(&scalar, int64(1)); err != nil {
		t.Fatalf("scalar GetMapWhere failed: %v", err)
	}
	if _, err := m.GetMapWhere(&scalar, "1"); !isNotFound(err) {
		t.Fatal("scalar GetMapWhere crossed integer and string domains")
	}
}

func TestEventIDFilterCompatibility(t *testing.T) {
	m := evtx.GoEvtxMap{
		"Event": evtx.GoEvtxMap{
			"System": evtx.GoEvtxMap{"EventID": int64(7)},
		},
	}

	if !m.IsEventID("7", int64(12)) {
		t.Fatal("legal string and integer EventID filters stopped matching")
	}
	if m.IsEventID(true, uint64(7)) {
		t.Fatal("EventID filter crossed numeric value domains")
	}

	missing := evtx.GoEvtxMap{}
	if missing.IsEventID(0, "0") {
		t.Fatal("missing EventID matched a filter")
	}

	invalid := evtx.GoEvtxMap{"Event": evtx.GoEvtxMap{"System": evtx.GoEvtxMap{"EventID": true}}}
	if invalid.IsEventID(true, "1") {
		t.Fatal("invalid EventID type matched a filter")
	}

	nestedID := evtx.GoEvtxMap{
		"Event": evtx.GoEvtxMap{
			"System": evtx.GoEvtxMap{
				"EventID": evtx.GoEvtxMap{"Value": int64(12)},
			},
		},
	}
	if !nestedID.IsEventID(12, "13") {
		t.Fatal("nested EventID filter did not match")
	}
}

func TestBetween(t *testing.T) {
	start := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Hour)

	for _, offset := range []time.Duration{0, time.Hour, 2 * time.Hour} {
		m := evtx.GoEvtxMap{
			"Event": evtx.GoEvtxMap{
				"System": evtx.GoEvtxMap{
					"TimeCreated": evtx.GoEvtxMap{"SystemTime": evtx.UTCTime(start.Add(offset))},
				},
			},
		}
		if !m.Between(start, end) {
			t.Fatalf("timestamp at %s not included in inclusive range", offset)
		}
	}

	before := evtx.GoEvtxMap{
		"Event": evtx.GoEvtxMap{
			"System": evtx.GoEvtxMap{
				"TimeCreated": evtx.GoEvtxMap{"SystemTime": evtx.UTCTime(start.Add(-time.Nanosecond))},
			},
		},
	}
	if before.Between(start, end) {
		t.Fatal("timestamp before range matched Between")
	}
}

func ptrPath(s string) *evtx.GoEvtxPath { p := evtx.Path(s); return &p }

func isNotFound(err error) bool {
	_, ok := err.(*evtx.ErrEvtxEltNotFound)
	return ok
}
