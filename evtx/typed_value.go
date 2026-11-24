package evtx

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Typed value markers used by ToJSON.  They make values which used to be
// serialized as plain strings recoverable after a JSON round trip.
const (
	TypedValueTypeFileTime = "filetime"
	TypedValueTypeGUID     = "guid"
	TypedValueTypeSID      = "sid"
)

// TypedValue is the JSON envelope used for values which carry more semantics
// than their textual representation.  Normal JSON strings, numbers, booleans
// and null values are intentionally not wrapped.
type TypedValue struct {
	Type  string      `json:"type"`
	Value interface{} `json:"value"`
}

type sidWireValue struct {
	Revision            uint8    `json:"Revision"`
	SubAuthorityCount   uint8    `json:"SubAuthorityCount"`
	IdentifierAuthority [6]uint8 `json:"IdentifierAuthority"`
	SubAuthority        []uint32 `json:"SubAuthority"`
}

func newTypedValue(typ string, value interface{}) TypedValue {
	return TypedValue{Type: typ, Value: value}
}

func typedValueEnvelope(v interface{}) (TypedValue, bool) {
	switch v := v.(type) {
	case TypedValue:
		if isTypedValueType(v.Type) {
			return v, true
		}
		return TypedValue{}, false
	case *TypedValue:
		if v == nil || !isTypedValueType(v.Type) {
			return TypedValue{}, false
		}
		return *v, true
	case map[string]interface{}:
		typ, _ := v["type"].(string)
		if !isTypedValueType(typ) {
			return TypedValue{}, false
		}
		return TypedValue{Type: typ, Value: v["value"]}, true
	case GoEvtxMap:
		envelope, ok := typedValueEnvelope(map[string]interface{}(v))
		return envelope, ok
	case FileTime:
		return newTypedValue(TypedValueTypeFileTime, v.Nanoseconds), true
	case *FileTime:
		if v == nil {
			return TypedValue{}, false
		}
		return newTypedValue(TypedValueTypeFileTime, v.Nanoseconds), true
	case GUID:
		return newTypedValue(TypedValueTypeGUID, v.String()), true
	case *GUID:
		if v == nil {
			return TypedValue{}, false
		}
		return newTypedValue(TypedValueTypeGUID, v.String()), true
	case Sid:
		return newTypedValue(TypedValueTypeSID, v), true
	case *Sid:
		if v == nil {
			return TypedValue{}, false
		}
		return newTypedValue(TypedValueTypeSID, *v), true
	default:
		return TypedValue{}, false
	}
}

func isTypedValueType(typ string) bool {
	return typ == TypedValueTypeFileTime || typ == TypedValueTypeGUID || typ == TypedValueTypeSID
}

// MarshalJSON keeps the Windows FILETIME epoch value instead of only emitting
// its converted RFC3339 representation.
func (f FileTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(newTypedValue(TypedValueTypeFileTime, f.Nanoseconds))
}

// UnmarshalJSON accepts both the typed envelope produced by MarshalJSON and a
// plain JSON number containing the Windows FILETIME value.
func (f *FileTime) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		f.Nanoseconds = 0
		return nil
	}
	var envelope struct {
		Type  string          `json:"type"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(data, &envelope); err == nil && envelope.Type != "" {
		if envelope.Type != TypedValueTypeFileTime {
			return fmt.Errorf("bad %s type %q", TypedValueTypeFileTime, envelope.Type)
		}
		nanoseconds, ok := unmarshalInt64(envelope.Value)
		if !ok {
			return fmt.Errorf("bad %s value: %s", TypedValueTypeFileTime, string(envelope.Value))
		}
		f.Nanoseconds = nanoseconds
		return nil
	}

	nanoseconds, ok := unmarshalInt64(data)
	if !ok {
		return fmt.Errorf("bad %s value: %s", TypedValueTypeFileTime, string(data))
	}
	f.Nanoseconds = nanoseconds
	return nil
}

// MarshalJSON keeps the GUID type alongside its canonical textual value.
func (g GUID) MarshalJSON() ([]byte, error) {
	return json.Marshal(newTypedValue(TypedValueTypeGUID, g.String()))
}

// UnmarshalJSON accepts both the typed envelope and an unwrapped GUID string.
func (g *GUID) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*g = GUID{}
		return nil
	}
	var envelope struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &envelope); err == nil && envelope.Type != "" {
		if envelope.Type != TypedValueTypeGUID {
			return fmt.Errorf("bad %s type %q", TypedValueTypeGUID, envelope.Type)
		}
		if envelope.Value == "" {
			return fmt.Errorf("bad %s value: %s", TypedValueTypeGUID, string(data))
		}
		return parseGUID(envelope.Value, g)
	}

	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	return parseGUID(s, g)
}

// MarshalJSON keeps the structured SID and its security identifier type.
func (s Sid) MarshalJSON() ([]byte, error) {
	return json.Marshal(newTypedValue(TypedValueTypeSID, sidWireValue(s)))
}

// UnmarshalJSON accepts both the typed envelope and an unwrapped SID string.
func (s *Sid) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*s = Sid{}
		return nil
	}
	var envelope struct {
		Type  string `json:"type"`
		Value json.RawMessage
	}
	if err := json.Unmarshal(data, &envelope); err == nil && envelope.Type != "" {
		if envelope.Type != TypedValueTypeSID {
			return fmt.Errorf("bad %s type %q", TypedValueTypeSID, envelope.Type)
		}
		if len(envelope.Value) == 0 || string(envelope.Value) == "null" {
			return fmt.Errorf("bad %s value: %s", TypedValueTypeSID, string(data))
		}
		var structured Sid
		var structuredJSON sidWireValue
		if err := json.Unmarshal(envelope.Value, &structuredJSON); err == nil {
			structured = Sid(structuredJSON)
			*s = structured
			return nil
		}
		var text string
		if err := json.Unmarshal(envelope.Value, &text); err != nil {
			return err
		}
		return parseSID(text, s)
	}

	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	return parseSID(text, s)
}

func typedValueString(v interface{}) (string, bool) {
	envelope, ok := typedValueEnvelope(v)
	if !ok {
		return "", false
	}

	switch envelope.Type {
	case TypedValueTypeFileTime:
		nanoseconds, ok := int64FromInterface(envelope.Value)
		if !ok {
			return "", false
		}
		return (&FileTime{Nanoseconds: nanoseconds}).String(), true
	case TypedValueTypeGUID:
		s, ok := envelope.Value.(string)
		return s, ok
	case TypedValueTypeSID:
		switch value := envelope.Value.(type) {
		case Sid:
			return (&ValueSID{value: value}).String(), true
		case *Sid:
			if value == nil {
				return "", false
			}
			return (&ValueSID{value: *value}).String(), true
		case string:
			return value, true
		case map[string]interface{}:
			structured, ok := sidFromMap(value)
			if !ok {
				return "", false
			}
			return (&ValueSID{value: structured}).String(), true
		}
	}
	return "", false
}

func sidFromMap(value map[string]interface{}) (Sid, bool) {
	sid := Sid{
		SubAuthority: make([]uint32, 0),
	}

	if revision, ok := int64FromInterface(value["Revision"]); ok {
		sid.Revision = uint8(revision)
	} else {
		return Sid{}, false
	}
	if subAuthorityCount, ok := int64FromInterface(value["SubAuthorityCount"]); ok {
		sid.SubAuthorityCount = uint8(subAuthorityCount)
	} else {
		return Sid{}, false
	}

	switch authority := value["IdentifierAuthority"].(type) {
	case []interface{}:
		if len(authority) != len(sid.IdentifierAuthority) {
			return Sid{}, false
		}
		for i, item := range authority {
			v, ok := int64FromInterface(item)
			if !ok {
				return Sid{}, false
			}
			sid.IdentifierAuthority[i] = uint8(v)
		}
	case [6]uint8:
		sid.IdentifierAuthority = authority
	case []uint8:
		if len(authority) != len(sid.IdentifierAuthority) {
			return Sid{}, false
		}
		copy(sid.IdentifierAuthority[:], authority)
	default:
		return Sid{}, false
	}

	// SubAuthority may be absent or null only when the SID has no
	// sub-authorities.
	if rawAuthorities := value["SubAuthority"]; rawAuthorities == nil {
		if sid.SubAuthorityCount != 0 {
			return Sid{}, false
		}
		return sid, true
	}

	switch authorities := value["SubAuthority"].(type) {
	case []interface{}:
		if len(authorities) != int(sid.SubAuthorityCount) {
			return Sid{}, false
		}
		sid.SubAuthority = make([]uint32, len(authorities))
		for i, item := range authorities {
			v, ok := int64FromInterface(item)
			if !ok {
				return Sid{}, false
			}
			sid.SubAuthority[i] = uint32(v)
		}
	case []uint32:
		if len(authorities) != int(sid.SubAuthorityCount) {
			return Sid{}, false
		}
		sid.SubAuthority = append(sid.SubAuthority, authorities...)
	default:
		return Sid{}, false
	}
	return sid, true
}

func typedValueTime(v interface{}) (time.Time, bool) {
	envelope, ok := typedValueEnvelope(v)
	if !ok || envelope.Type != TypedValueTypeFileTime {
		return time.Time{}, false
	}

	nanoseconds, ok := int64FromInterface(envelope.Value)
	if !ok {
		return time.Time{}, false
	}
	return time.Time((&FileTime{Nanoseconds: nanoseconds}).Time()), true
}

func int64FromInterface(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		return int64(n), true
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), true
	case float64:
		if n != float64(int64(n)) {
			return 0, false
		}
		return int64(n), true
	case float32:
		if n != float32(int64(n)) {
			return 0, false
		}
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	default:
		return 0, false
	}
}

func unmarshalInt64(data json.RawMessage) (int64, bool) {
	var number json.Number
	if err := json.Unmarshal(data, &number); err != nil {
		return 0, false
	}
	if i, err := number.Int64(); err == nil {
		return i, true
	}
	f, err := number.Float64()
	return int64(f), err == nil && f == float64(int64(f))
}

func typedValueEqual(a, b interface{}) bool {
	ea, okA := typedValueEnvelope(a)
	eb, okB := typedValueEnvelope(b)
	if okA != okB {
		// Preserve the historical convenience of comparing a GUID or SID value
		// with its textual representation.
		if text, ok := typedValueString(a); ok {
			return text == b
		}
		if text, ok := typedValueString(b); ok {
			return text == a
		}
		return false
	}
	if !okA {
		return false
	}
	if ea.Type != eb.Type {
		return false
	}

	if textA, ok := typedValueString(ea); ok {
		textB, ok := typedValueString(eb)
		return ok && textA == textB
	}
	return false
}

func parseGUID(text string, guid *GUID) error {
	parts := strings.Split(text, "-")
	if len(parts) != 5 || len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 ||
		len(parts[3]) != 4 || len(parts[4]) != 12 {
		return fmt.Errorf("invalid GUID: %s", text)
	}

	hexParts := make([]string, 0, 16)
	hexParts = append(hexParts,
		parts[0][0:2], parts[0][2:4], parts[0][4:6], parts[0][6:8],
		parts[1][0:2], parts[1][2:4],
		parts[2][0:2], parts[2][2:4],
		parts[3][0:2], parts[3][2:4])
	for i := 0; i < len(parts[4]); i += 2 {
		hexParts = append(hexParts, parts[4][i:i+2])
	}

	for i, hexPart := range hexParts {
		v, err := strconv.ParseUint(hexPart, 16, 8)
		if err != nil {
			return fmt.Errorf("invalid GUID %q: %w", text, err)
		}
		guid[i] = byte(v)
	}

	// GUID's first three components are little endian on the wire.
	guid[0], guid[3] = guid[3], guid[0]
	guid[1], guid[2] = guid[2], guid[1]
	guid[4], guid[5] = guid[5], guid[4]
	guid[6], guid[7] = guid[7], guid[6]
	return nil
}

func parseSID(text string, sid *Sid) error {
	parts := strings.Split(text, "-")
	if len(parts) < 3 || parts[0] != "S" {
		return fmt.Errorf("invalid SID: %s", text)
	}

	revision, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return fmt.Errorf("invalid SID revision %q: %w", text, err)
	}
	authority, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid SID authority %q: %w", text, err)
	}

	*sid = Sid{
		Revision:          uint8(revision),
		SubAuthorityCount: uint8(len(parts) - 3),
		SubAuthority:      make([]uint32, len(parts)-3),
	}
	for i := 5; i >= 0; i-- {
		sid.IdentifierAuthority[i] = byte(authority)
		authority >>= 8
	}
	for i, part := range parts[3:] {
		authority, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid SID sub-authority %q: %w", text, err)
		}
		sid.SubAuthority[i] = uint32(authority)
	}
	return nil
}
