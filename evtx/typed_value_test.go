package evtx

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTypedValuesToJSON(t *testing.T) {
	fileTime := FileTime{Nanoseconds: 131294208000000000}
	guid := GUID{0x5f, 0x38, 0x70, 0x57, 0x2a, 0xc2, 0xe0, 0x43, 0xbf, 0x4c, 0x06, 0xf5, 0x69, 0x8f, 0xfb, 0xd9}
	sid := Sid{
		Revision:            1,
		SubAuthorityCount:   5,
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
		SubAuthority:        []uint32{21, 1, 2, 3, 500},
	}

	m := GoEvtxMap{
		"FileTime": fileTime,
		"GUID":     guid,
		"SID":      sid,
		"Number":   42,
		"String":   "plain",
		"Boolean":  true,
		"Null":     nil,
	}

	data := ToJSON(m)
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"FileTime", "GUID", "SID"} {
		envelope, ok := decoded[key].(map[string]interface{})
		if !ok {
			t.Fatalf("%s did not keep a typed envelope: %v", key, decoded[key])
		}
		if _, ok := envelope["type"]; !ok {
			t.Fatalf("%s envelope is missing type: %v", key, envelope)
		}
		if _, ok := envelope["value"]; !ok {
			t.Fatalf("%s envelope is missing value: %v", key, envelope)
		}
	}

	if got := decoded["FileTime"].(map[string]interface{})["type"]; got != TypedValueTypeFileTime {
		t.Fatalf("unexpected FileTime type: %v", got)
	}
	if got := decoded["FileTime"].(map[string]interface{})["value"].(float64); int64(got) != fileTime.Nanoseconds {
		t.Fatalf("unexpected FileTime value: %v", got)
	}
	if got := decoded["GUID"].(map[string]interface{})["value"]; got != guid.String() {
		t.Fatalf("unexpected GUID value: %v", got)
	}
	sidEnvelope := decoded["SID"].(map[string]interface{})
	if got := sidEnvelope["type"]; got != TypedValueTypeSID {
		t.Fatalf("unexpected SID type: %v", got)
	}
	sidValue := sidEnvelope["value"].(map[string]interface{})
	if got := sidValue["SubAuthorityCount"].(float64); int(got) != len(sid.SubAuthority) {
		t.Fatalf("unexpected SID sub-authority count: %v", got)
	}

	if got := decoded["Number"].(float64); got != 42 {
		t.Fatalf("number was wrapped or changed: %v", decoded["Number"])
	}
	if got := decoded["String"]; got != "plain" {
		t.Fatalf("string was wrapped or changed: %v", got)
	}
	if got := decoded["Boolean"]; got != true {
		t.Fatalf("boolean was wrapped or changed: %v", got)
	}
	if got, ok := decoded["Null"]; !ok || got != nil {
		t.Fatalf("null was wrapped or changed: %v", got)
	}
}

func TestTypedValueRoundTrip(t *testing.T) {
	guid := GUID{0x5f, 0x38, 0x70, 0x57, 0x2a, 0xc2, 0xe0, 0x43, 0xbf, 0x4c, 0x06, 0xf5, 0x69, 0x8f, 0xfb, 0xd9}
	sid := Sid{
		Revision:            1,
		SubAuthorityCount:   5,
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
		SubAuthority:        []uint32{21, 1, 2, 3, 500},
	}

	var decodedGUID GUID
	if err := json.Unmarshal(ToJSON(guid), &decodedGUID); err != nil {
		t.Fatal(err)
	}
	if decodedGUID.String() != guid.String() {
		t.Fatalf("GUID round trip mismatch: %s != %s", decodedGUID, guid)
	}

	var decodedSID Sid
	if err := json.Unmarshal(ToJSON(sid), &decodedSID); err != nil {
		t.Fatal(err)
	}
	if (&ValueSID{value: decodedSID}).String() != (&ValueSID{value: sid}).String() {
		t.Fatalf("SID round trip mismatch: %s != %s", (&ValueSID{value: decodedSID}).String(), (&ValueSID{value: sid}).String())
	}

	fileTime := FileTime{Nanoseconds: 131294208000000000}
	var decodedFileTime FileTime
	if err := json.Unmarshal(ToJSON(fileTime), &decodedFileTime); err != nil {
		t.Fatal(err)
	}
	if decodedFileTime.Nanoseconds != fileTime.Nanoseconds {
		t.Fatalf("FileTime round trip mismatch: %d != %d", decodedFileTime.Nanoseconds, fileTime.Nanoseconds)
	}

	var decodedEnvelopeFileTime FileTime
	if err := json.Unmarshal([]byte(`{"type":"filetime","value":131294208000000000.0}`), &decodedEnvelopeFileTime); err != nil {
		t.Fatal(err)
	}
	if decodedEnvelopeFileTime.Nanoseconds != fileTime.Nanoseconds {
		t.Fatalf("decoded FileTime envelope mismatch: %d != %d", decodedEnvelopeFileTime.Nanoseconds, fileTime.Nanoseconds)
	}
}

func TestTypedValueLegacyTextAndNumberUnmarshal(t *testing.T) {
	guid := GUID{0x5f, 0x38, 0x70, 0x57, 0x2a, 0xc2, 0xe0, 0x43, 0xbf, 0x4c, 0x06, 0xf5, 0x69, 0x8f, 0xfb, 0xd9}
	var decodedGUID GUID
	if err := json.Unmarshal([]byte(`"`+guid.String()+`"`), &decodedGUID); err != nil {
		t.Fatal(err)
	}
	if decodedGUID.String() != guid.String() {
		t.Fatalf("legacy GUID unmarshal mismatch: %s != %s", decodedGUID, guid)
	}

	var decodedSID Sid
	if err := json.Unmarshal([]byte(`"S-1-5-21-1-2-3-500"`), &decodedSID); err != nil {
		t.Fatal(err)
	}
	if got := (&ValueSID{value: decodedSID}).String(); got != "S-1-5-21-1-2-3-500" {
		t.Fatalf("legacy SID unmarshal mismatch: %s", got)
	}

	var authorityOnlySID Sid
	if err := json.Unmarshal([]byte(`"S-1-5"`), &authorityOnlySID); err != nil {
		t.Fatal(err)
	}
	if got := (&ValueSID{value: authorityOnlySID}).String(); got != "S-1-5" {
		t.Fatalf("authority-only SID unmarshal mismatch: %s", got)
	}

	fileTime := FileTime{Nanoseconds: 131294208000000000}
	var decodedFileTime FileTime
	if err := json.Unmarshal([]byte(`131294208000000000`), &decodedFileTime); err != nil {
		t.Fatal(err)
	}
	if decodedFileTime.Nanoseconds != fileTime.Nanoseconds {
		t.Fatalf("legacy FileTime unmarshal mismatch: %d != %d", decodedFileTime.Nanoseconds, fileTime.Nanoseconds)
	}
}

func TestTypedValueNilAndEnvelopeValidation(t *testing.T) {
	m := GoEvtxMap{"Custom": TypedValue{Type: "custom", Value: "value"}}
	var decoded map[string]interface{}
	if err := json.Unmarshal(ToJSON(m), &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["Custom"].(map[string]interface{}); !ok {
		t.Fatalf("custom envelope should remain a normal JSON object: %#v", decoded["Custom"])
	}
	if _, ok := typedValueString(decoded["Custom"]); ok {
		t.Fatal("custom envelope must not be interpreted as a security typed value")
	}
}

func TestGoEvtxMapTypedConsumers(t *testing.T) {
	guidPath := Path("/GUID")
	sidPath := Path("/SID")
	stringPath := Path("/String")
	intPath := Path("/Int")
	uintPath := Path("/Uint")
	boolPath := Path("/Boolean")
	fileTimePath := Path("/FileTime")
	nullPath := Path("/Null")

	fileTime := FileTime{Nanoseconds: 131294208000000000}
	guid := GUID{0x5f, 0x38, 0x70, 0x57, 0x2a, 0xc2, 0xe0, 0x43, 0xbf, 0x4c, 0x06, 0xf5, 0x69, 0x8f, 0xfb, 0xd9}
	sid := Sid{
		Revision:            1,
		SubAuthorityCount:   5,
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
		SubAuthority:        []uint32{21, 1, 2, 3, 500},
	}

	m := GoEvtxMap{
		"FileTime": fileTime,
		"GUID":     guid,
		"SID":      sid,
		"Int":      int64(42),
		"Uint":     uint64(43),
		"String":   "plain",
		"Boolean":  true,
		"Null":     nil,
	}

	if got, err := m.GetString(&guidPath); err != nil || got != guid.String() {
		t.Fatalf("GUID GetString mismatch: %q, %v", got, err)
	}
	if got, err := m.GetString(&sidPath); err != nil || got != "S-1-5-21-1-2-3-500" {
		t.Fatalf("SID GetString mismatch: %q, %v", got, err)
	}
	if got, err := m.GetString(&stringPath); err != nil || got != "plain" {
		t.Fatalf("string GetString mismatch: %q, %v", got, err)
	}
	if got, err := m.GetInt(&intPath); err != nil || got != 42 {
		t.Fatalf("GetInt mismatch: %d, %v", got, err)
	}
	if got, err := m.GetUint(&uintPath); err != nil || got != 43 {
		t.Fatalf("GetUint mismatch: %d, %v", got, err)
	}
	if got, err := m.GetBool(&boolPath); err != nil || !got {
		t.Fatalf("GetBool mismatch: %v, %v", got, err)
	}
	if got, err := m.GetTime(&fileTimePath); err != nil || !got.Equal(time.Time(fileTime.Time())) {
		t.Fatalf("GetTime mismatch: %v, %v", got, err)
	}
	if got, err := m.GetString(&fileTimePath); err != nil || got != fileTime.String() {
		t.Fatalf("FileTime GetString mismatch: %q, %v", got, err)
	}
	if !m.Equal(&guidPath, guid.String()) {
		t.Fatal("typed GUID should remain comparable to its textual value")
	}
	if !m.Equal(&sidPath, "S-1-5-21-1-2-3-500") {
		t.Fatal("typed SID should remain comparable to its textual value")
	}
	if !m.AnyEqual(&guidPath, []interface{}{guid.String()}) {
		t.Fatal("typed GUID should remain comparable through AnyEqual")
	}
	wherePath := Path("/Record/GUID")
	record := GoEvtxMap{
		"Record": GoEvtxMap{
			"GUID": guid,
		},
	}
	found, err := record.GetMapWhere(&wherePath, guid.String())
	if err != nil || found == nil {
		t.Fatalf("GetMapWhere should preserve typed GUID matching: %v", err)
	}
	if _, err := m.Get(&nullPath); err != nil {
		t.Fatalf("null value should remain readable: %v", err)
	}

	securityPath := Path("/Event/System/Security")
	security := GoEvtxMap{
		"Event": GoEvtxMap{
			"System": GoEvtxMap{
				"Security": GoEvtxMap{
					"UserID": sid,
				},
			},
		},
	}
	if got, ok := security.UserID(); !ok || got != "S-1-5-21-1-2-3-500" {
		t.Fatalf("UserID semantic mismatch: %q, %v", got, ok)
	}
	if _, err := security.GetMap(&securityPath); err != nil {
		t.Fatalf("Security path should remain readable: %v", err)
	}
}

func TestDecodedTypedEnvelopeConsumers(t *testing.T) {
	guidPath := Path("/GUID")
	sidPath := Path("/SID")
	fileTimePath := Path("/FileTime")

	fileTime := FileTime{Nanoseconds: 131294208000000000}
	guid := GUID{0x5f, 0x38, 0x70, 0x57, 0x2a, 0xc2, 0xe0, 0x43, 0xbf, 0x4c, 0x06, 0xf5, 0x69, 0x8f, 0xfb, 0xd9}
	sid := Sid{
		Revision:            1,
		SubAuthorityCount:   5,
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
		SubAuthority:        []uint32{21, 1, 2, 3, 500},
	}

	var decoded GoEvtxMap
	if err := json.Unmarshal(ToJSON(GoEvtxMap{
		"FileTime": fileTime,
		"GUID":     guid,
		"SID":      sid,
	}), &decoded); err != nil {
		t.Fatal(err)
	}
	if got, err := decoded.GetString(&guidPath); err != nil || got != guid.String() {
		t.Fatalf("decoded GUID GetString mismatch: %q, %v", got, err)
	}
	if got, err := decoded.GetString(&sidPath); err != nil || got != "S-1-5-21-1-2-3-500" {
		t.Fatalf("decoded SID GetString mismatch: %q, %v", got, err)
	}
	if got, err := decoded.GetTime(&fileTimePath); err != nil || !got.Equal(time.Time(fileTime.Time())) {
		t.Fatalf("decoded FileTime GetTime mismatch: %v, %v", got, err)
	}
	if got, err := decoded.GetString(&fileTimePath); err != nil || got != fileTime.String() {
		t.Fatalf("decoded FileTime GetString mismatch: %q, %v", got, err)
	}
}

func TestDecodedPlainJSONValuesRemainReadable(t *testing.T) {
	var decoded GoEvtxMap
	if err := json.Unmarshal([]byte(`{
		"Number": 42,
		"String": "plain",
		"Boolean": true,
		"Null": null
	}`), &decoded); err != nil {
		t.Fatal(err)
	}

	numberPath := Path("/Number")
	stringPath := Path("/String")
	boolPath := Path("/Boolean")
	nullPath := Path("/Null")

	if got, err := decoded.GetInt(&numberPath); err != nil || got != 42 {
		t.Fatalf("decoded number mismatch: %d, %v", got, err)
	}
	if got, err := decoded.GetString(&stringPath); err != nil || got != "plain" {
		t.Fatalf("decoded string mismatch: %q, %v", got, err)
	}
	if got, err := decoded.GetBool(&boolPath); err != nil || !got {
		t.Fatalf("decoded boolean mismatch: %v, %v", got, err)
	}
	value, err := decoded.Get(&nullPath)
	if err != nil {
		t.Fatalf("decoded null should remain readable: %v", err)
	}
	if *value != nil {
		t.Fatalf("decoded null changed: %#v", *value)
	}
}
