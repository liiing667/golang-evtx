package evtx

import "testing"

func TestScalarValueReprPreservesTypes(t *testing.T) {
	tests := []struct {
		name string
		v    Value
		want interface{}
	}{
		{"bool", &ValueBool{ValueInt32{value: 1}}, true},
		{"int8", &ValueInt8{value: -8}, int8(-8)},
		{"uint8", &ValueUInt8{value: 8}, uint8(8)},
		{"int16", &ValueInt16{value: -16}, int16(-16)},
		{"uint16", &ValueUInt16{value: 16}, uint16(16)},
		{"int32", &ValueInt32{value: -32}, int32(-32)},
		{"uint32", &ValueUInt32{value: 32}, uint32(32)},
		{"hex int32", &ValueHexInt32{ValueUInt32{value: 32}}, uint32(32)},
		{"int64", &ValueInt64{value: -64}, int64(-64)},
		{"uint64", &ValueUInt64{value: 64}, uint64(64)},
		{"hex int64", &ValueHexInt64{ValueUInt64{value: 64}}, uint64(64)},
	}

	for _, tc := range tests {
		if got := tc.v.Repr(); got != tc.want {
			t.Fatalf("%s: got %T(%v), want %T(%v)", tc.name, got, got, tc.want, tc.want)
		}
	}
}
