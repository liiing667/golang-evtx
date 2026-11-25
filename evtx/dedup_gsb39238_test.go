package evtx

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func gsbEvent(id interface{}) *GoEvtxMap {
	return &GoEvtxMap{
		"Event": GoEvtxMap{
			"System": GoEvtxMap{
				"EventRecordID": id,
			},
		},
	}
}

func TestGSB39238RecordDeduperCrossChunks(t *testing.T) {
	d := NewRecordDeduper("test").SetSource("dirty.evtx")

	chunk1 := []eventEnvelope{
		{event: Event{Offset: 0x200, Header: EventHeader{ID: 1}}, gem: gsbEvent("1"), chunkOffset: 0x1000},
		{event: Event{Offset: 0x300, Header: EventHeader{ID: 2}}, gem: gsbEvent(int64(2)), chunkOffset: 0x1000},
	}
	chunk2 := []eventEnvelope{
		{event: Event{Offset: 0x200, Header: EventHeader{ID: 3}}, gem: gsbEvent("3"), chunkOffset: 0x2000},
		{event: Event{Offset: 0x400, Header: EventHeader{ID: 1}}, gem: gsbEvent("1"), chunkOffset: 0x2000},
	}

	published := 0
	for _, envs := range [][]eventEnvelope{chunk1, chunk2} {
		for _, env := range envs {
			if _, ok := d.Admit(env); ok {
				published++
			}
		}
	}

	if published != 3 {
		t.Fatalf("expected IDs 1,2,3 published, got %d", published)
	}
	if got := d.Count(); got != 1 {
		t.Fatalf("expected one conflict evidence, got %d", got)
	}
	rs := d.RejectedRecords()
	r := rs[0]
	if r.RecordID != 1 || r.EventRecordID() != 1 || r.ID != 1 {
		t.Fatalf("bad identity in evidence: %+v", r)
	}
	if r.Stage != "test" || r.Source != "dirty.evtx" {
		t.Fatalf("evidence missing stage/source: %+v", r)
	}
	if r.ChunkOffset != 0x2000 || r.Offset != 0x400 || r.AbsoluteOffset != 0x2400 {
		t.Fatalf("bad rejected coordinates: %+v", r)
	}
	if r.FirstChunkOffset != 0x1000 || r.FirstOffset != 0x200 || r.FirstAbsoluteOffset != 0x1200 {
		t.Fatalf("bad first coordinates: %+v", r)
	}
	if r.Event == nil || r.Event.EventRecordID() != 1 {
		t.Fatalf("retained event identity wrong: %+v", r.Event)
	}
	if !errors.Is(r, ErrDuplicateRecordID) {
		t.Fatalf("rejection must wrap duplicate sentinel: %v", r.Err)
	}
	if js := string(ToJSON(r)); !strings.Contains(js, `"EventRecordID":1`) || !strings.Contains(js, `"stage":"test"`) {
		t.Fatalf("rejection JSON lost identity/stage: %s", js)
	}
}

func TestGSB39238ZeroIdentityPasses(t *testing.T) {
	d := NewRecordDeduper()
	for i := 0; i < 2; i++ {
		if _, ok := d.Admit(eventEnvelope{gem: gsbEvent("not-an-int")}); !ok {
			t.Fatal("unreadable identity must preserve legacy pass-through")
		}
	}
	if d.Count() != 0 {
		t.Fatalf("unexpected evidence: %+v", d.Rejected())
	}
}

func TestGSB39238NewTruncatedHeaderDoesNotPanic(t *testing.T) {
	data := make([]byte, 96)
	copy(data, []byte("ElfFile\x00"))
	if _, err := New(bytes.NewReader(data)); err == nil {
		t.Fatal("truncated header must return an error")
	}
}
