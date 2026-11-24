package evtx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func gsb39245HeaderBytes(chunkCount uint16) []byte {
	var header FileHeader
	copy(header.Magic[:], EvtxMagic)
	header.ChunkDataOffset = ChunkHeaderSize
	header.ChunkCount = chunkCount

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &header); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func gsb39245Drain(t *testing.T, events <-chan *GoEvtxMap) int {
	t.Helper()
	n := 0
	for range events {
		n++
	}
	return n
}

func TestGSB39245ResetReloadsCommittedHeaderAndCursor(t *testing.T) {
	data := gsb39245HeaderBytes(0)
	reader := bytes.NewReader(data)

	ef, err := New(reader)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate stale state left by an older traversal/generation.
	ef.Header.ChunkCount = 99
	if _, err := reader.Seek(7, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	binary.LittleEndian.PutUint16(data[42:44], 2)

	if err := ef.Reset(); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	if ef.Header.ChunkCount != 2 {
		t.Fatalf("Reset did not reload committed header: count=%d", ef.Header.ChunkCount)
	}

	current, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(binary.Size(FileHeader{})); current != want {
		t.Fatalf("header cursor=%d, want %d", current, want)
	}
}

func TestGSB39245ReopenPathUsesNewCommittedState(t *testing.T) {
	dir, err := ioutil.TempDir("", "evtx-reopen-39245")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "committed.evtx")
	if err := ioutil.WriteFile(path, gsb39245HeaderBytes(0), 0600); err != nil {
		t.Fatal(err)
	}

	ef, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if ef.path != path {
		t.Fatalf("Open did not remember path: %q", ef.path)
	}
	if err := ef.Close(); err != nil {
		t.Fatal(err)
	}

	if err := ioutil.WriteFile(path, gsb39245HeaderBytes(3), 0600); err != nil {
		t.Fatal(err)
	}

	if err := ef.Reopen(); err != nil {
		t.Fatalf("Reopen after Close failed: %v", err)
	}
	defer ef.Close()

	if ef.Header.ChunkCount != 3 {
		t.Fatalf("Reopen inherited stale header, count=%d", ef.Header.ChunkCount)
	}
	if state := ef.CommittedState(); state.ChunkCount != 3 {
		t.Fatalf("CommittedState count=%d, want 3", state.ChunkCount)
	}
	if ef.path != path {
		t.Fatalf("Reopen lost path: %q", ef.path)
	}
}

func TestGSB39245CompleteTraversalCanRepeat(t *testing.T) {
	ef, err := New(bytes.NewReader(gsb39245HeaderBytes(0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()

	for i := 0; i < 2; i++ {
		if n := gsb39245Drain(t, ef.Events()); n != 0 {
			t.Fatalf("Events traversal %d emitted %d events for empty log", i, n)
		}
		if n := gsb39245Drain(t, ef.FastEvents()); n != 0 {
			t.Fatalf("FastEvents traversal %d emitted %d events for empty log", i, n)
		}
		if n := gsb39245Drain(t, ef.UnorderedEvents()); n != 0 {
			t.Fatalf("UnorderedEvents traversal %d emitted %d events for empty log", i, n)
		}
	}
}

func TestGSB39245ZeroValueFileStreamsEmpty(t *testing.T) {
	var ef File

	if n := gsb39245Drain(t, ef.Events()); n != 0 {
		t.Fatalf("zero File Events emitted %d", n)
	}
	if n := gsb39245Drain(t, ef.FastEvents()); n != 0 {
		t.Fatalf("zero File FastEvents emitted %d", n)
	}
	if n := gsb39245Drain(t, ef.UnorderedEvents()); n != 0 {
		t.Fatalf("zero File UnorderedEvents emitted %d", n)
	}
}

func gsb39245PutSyntheticEvent(data []byte, offset int32, recordID uint64, size int32) {
	copy(data[offset:offset+4], EventMagic)
	binary.LittleEndian.PutUint32(data[offset+4:offset+8], uint32(size))
	binary.LittleEndian.PutUint64(data[offset+8:offset+16], recordID)

	data[offset+24] = FragmentHeaderToken
	data[offset+25] = 1
	data[offset+26] = 1
	data[offset+27] = 0
	data[offset+28] = TokenTemplateInstance
	binary.LittleEndian.PutUint32(data[offset+34:offset+38], 0x900)
}

func gsb39245TwoEventFile() []byte {
	chunk := make([]byte, ChunkSize)
	binary.LittleEndian.PutUint32(chunk[40:44], ChunkHeaderSize)
	binary.LittleEndian.PutUint32(chunk[44:48], 768) // OffsetLastRec
	// First template-bucket entry points at the empty template definition.
	binary.LittleEndian.PutUint32(chunk[0x180:0x184], 0x900)

	template := int32(0x900)
	chunk[template+24] = FragmentHeaderToken
	chunk[template+25] = 1
	chunk[template+26] = 1
	chunk[template+27] = 0
	chunk[template+28] = TokenEOF

	gsb39245PutSyntheticEvent(chunk, 512, 1, 256)
	gsb39245PutSyntheticEvent(chunk, 768, 2, 256)

	return append(gsb39245HeaderBytes(1), chunk...)
}

func TestGSB39245CompleteSyntheticTraversalSurvivesReopen(t *testing.T) {
	ef, err := New(bytes.NewReader(gsb39245TwoEventFile()))
	if err != nil {
		t.Fatal(err)
	}

	for traversal := 0; traversal < 2; traversal++ {
		if n := gsb39245Drain(t, ef.Events()); n != 2 {
			t.Fatalf("Events traversal %d emitted %d events, want 2", traversal, n)
		}
		if n := gsb39245Drain(t, ef.FastEvents()); n != 2 {
			t.Fatalf("FastEvents traversal %d emitted %d events, want 2", traversal, n)
		}
	}

	if err := ef.Reopen(); err != nil {
		t.Fatalf("reader reopen failed: %v", err)
	}
	if n := gsb39245Drain(t, ef.Events()); n != 2 {
		t.Fatalf("Events after Reopen emitted %d events, want 2", n)
	}
}

func TestGSB39245ChunkTablesDoNotSurviveReparse(t *testing.T) {
	chunk := NewChunk()
	chunk.Offset = 0x1000
	chunk.Data = []byte("committed-bytes")
	chunk.TemplateTable[0x1234] = TemplateDefinitionData{}
	chunk.EventOffsets = []int32{512}

	templateReader := bytes.NewReader(make([]byte, sizeTemplateBucket*4))
	if err := chunk.ParseTemplateTable(templateReader); err != nil {
		t.Fatal(err)
	}
	if _, stale := chunk.TemplateTable[0x1234]; stale || len(chunk.TemplateTable) != 0 {
		t.Fatalf("stale template cache survived reparse: %#v", chunk.TemplateTable)
	}

	chunk.StringTable[0x4321] = ChunkString{}
	stringReader := bytes.NewReader(make([]byte, sizeStringBucket*4))
	chunk.ParseStringTable(stringReader)
	if _, stale := chunk.StringTable[0x4321]; stale || len(chunk.StringTable) != 0 {
		t.Fatalf("stale string table survived reparse: %#v", chunk.StringTable)
	}

	chunk.ResetParseState()
	if chunk.Offset != 0x1000 || string(chunk.Data) != "committed-bytes" {
		t.Fatal("ResetParseState should retain chunk identity and backing data")
	}
	if chunk.EventOffsets != nil || len(chunk.TemplateTable) != 0 {
		t.Fatal("ResetParseState did not clear old cursor/cache")
	}

	chunk.Reset()
	if chunk.Offset != 0 || chunk.Data != nil || chunk.TemplateTable == nil {
		t.Fatal("Reset did not return Chunk to a fresh state")
	}
}

func TestGSB39245ChunkEventsDeduplicateHeaderRecordID(t *testing.T) {
	data := gsb39245TwoEventFile()
	secondRecordIDOffset := int64(ChunkHeaderSize) + 768 + 8
	binary.LittleEndian.PutUint64(data[secondRecordIDOffset:secondRecordIDOffset+8], 1)

	ef, err := New(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	chunk, err := ef.FetchChunk(int64(ChunkHeaderSize))
	if err != nil {
		t.Fatal(err)
	}

	if n := gsb39245Drain(t, chunk.Events()); n != 1 {
		t.Fatalf("duplicate chunk record emitted %d events, want 1", n)
	}
}

func gsb39245RecordEvent(id uint64) *GoEvtxMap {
	return &GoEvtxMap{
		"Event": GoEvtxMap{
			"System": GoEvtxMap{
				"EventRecordID": fmt.Sprintf("%d", id),
			},
		},
	}
}

func TestGSB39245ReplayFilterResetsPerTraversal(t *testing.T) {
	filter := newEventReplayFilter()
	first := gsb39245RecordEvent(7)
	duplicate := gsb39245RecordEvent(7)
	next := gsb39245RecordEvent(8)

	if !filter.admit(first) {
		t.Fatal("first committed record must be admitted")
	}
	if filter.admit(duplicate) {
		t.Fatal("duplicate committed record must be filtered within one traversal")
	}
	if !filter.admit(next) {
		t.Fatal("later committed record must be admitted")
	}

	missingIdentity := &GoEvtxMap{}
	if !filter.admit(missingIdentity) {
		t.Fatal("event without record identity should preserve legacy pass-through")
	}

	var nilEvent *GoEvtxMap
	if !filter.admit(nilEvent) {
		t.Fatal("nil events must preserve historical pass-through behavior")
	}

	reopened := newEventReplayFilter()
	if !reopened.admit(gsb39245RecordEvent(7)) {
		t.Fatal("a new traversal/reopen must not inherit the old cursor/filter")
	}
}
