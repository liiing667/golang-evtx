package evtx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func testGem39243(id interface{}) *GoEvtxMap {
	return &GoEvtxMap{
		"Event": GoEvtxMap{
			"System": GoEvtxMap{
				"EventRecordID": id,
			},
		},
	}
}

func TestRecordDeduperCrossScanIdentity39243(t *testing.T) {
	d := NewRecordDeduper("OpenDirty").SetSource("dirty.evtx")

	observations := []eventEnvelope{
		{event: Event{Offset: 0x200, Header: EventHeader{ID: 1}}, gem: testGem39243("1"), chunkOffset: 0x1000},
		{event: Event{Offset: 0x300, Header: EventHeader{ID: 2}}, gem: testGem39243(int64(2)), chunkOffset: 0x1000},
		{event: Event{Offset: 0x200, Header: EventHeader{ID: 3}}, gem: testGem39243("3"), chunkOffset: 0x2000},
		// Reopened scan finds record 1 at another carved coordinate.
		{event: Event{Offset: 0x400, Header: EventHeader{ID: 1}}, gem: testGem39243("1"), chunkOffset: 0x2000},
	}

	published := 0
	for _, env := range observations {
		if _, ok := d.Admit(env); ok {
			published++
		}
	}

	if published != 3 {
		t.Fatalf("expected three unique records, published %d", published)
	}
	if d.Count() != 1 {
		t.Fatalf("expected one duplicate evidence, got %d", d.Count())
	}

	r := d.RejectedRecords()[0]
	if r.RecordID != 1 || r.EventRecordID != 1 || r.ID != 1 {
		t.Fatalf("bad record identity: %+v", r)
	}
	if r.ChunkOffset != 0x2000 || r.Offset != 0x400 || r.AbsoluteOffset != 0x2400 || r.SourceOffset != 0x2400 {
		t.Fatalf("bad current source coordinates: %+v", r)
	}
	if r.FirstChunkOffset != 0x1000 || r.FirstOffset != 0x200 || r.FirstAbsoluteOffset != 0x1200 {
		t.Fatalf("bad first source coordinates: %+v", r.First)
	}
	if r.Event == nil || r.Event.EventRecordID() != 1 {
		t.Fatalf("duplicate event evidence was not retained: %+v", r.Event)
	}
	if !errors.Is(r, ErrDuplicateRecordID) {
		t.Fatalf("rejection does not wrap duplicate sentinel: %v", r.Err)
	}
}

func TestRecordDeduperKeepsZeroAndDistinctIdentity39243(t *testing.T) {
	d := NewRecordDeduper()

	// Identical bytes without a readable non-zero record identity remain
	// pass-through observations.
	for i := 0; i < 2; i++ {
		if _, ok := d.Admit(eventEnvelope{gem: &GoEvtxMap{}}); !ok {
			t.Fatal("zero identity must preserve legacy pass-through")
		}
	}

	// Byte-identical synthetic records with different record identities are
	// legal distinct records and must both pass.
	for _, id := range []int64{7, 8} {
		env := eventEnvelope{event: Event{Offset: 512, Header: EventHeader{ID: id}}}
		if _, ok := d.Admit(env); !ok {
			t.Fatalf("distinct identity %d was rejected", id)
		}
	}
	if d.Count() != 0 {
		t.Fatalf("unexpected duplicates: %+v", d.Rejected())
	}
}

func TestAnnotateSourceOffsets39243(t *testing.T) {
	gem := AnnotateSource(&GoEvtxMap{}, 0x4000, 0x180)

	if got, ok := gem.SourceOffset(); !ok || got != 0x4180 {
		t.Fatalf("source offset = %d, %v", got, ok)
	}
	if got, ok := gem.ChunkOffset(); !ok || got != 0x4000 {
		t.Fatalf("chunk offset = %d, %v", got, ok)
	}
	if got, ok := gem.EventOffset(); !ok || got != 0x180 {
		t.Fatalf("event offset = %d, %v", got, ok)
	}
	if (*gem)["AbsoluteOffset"] != int64(0x4180) || (*gem)["FileOffset"] != int64(0x4180) {
		t.Fatalf("missing absolute offset aliases: %v", gem)
	}
}

func testHeaderBytes39243(chunkCount uint16, flags uint32) []byte {
	data := make([]byte, 128)
	copy(data[0:8], "ElfFile\x00")
	binary.LittleEndian.PutUint16(data[40:42], 128) // ChunkDataOffset
	binary.LittleEndian.PutUint16(data[42:44], chunkCount)
	binary.LittleEndian.PutUint32(data[120:124], flags)
	return data
}

func TestOpenDirtyCrossScanDeduper39243(t *testing.T) {
	ResetOpenDirtyDedupers()

	dir := t.TempDir()
	path := filepath.Join(dir, "dirty.evtx")
	if err := os.WriteFile(path, testHeaderBytes39243(0, 1), 0600); err != nil {
		t.Fatal(err)
	}

	f, err := OpenDirty(path)
	if err != nil {
		t.Fatalf("OpenDirty repaired header: %v", err)
	}
	defer f.Close()

	if !f.CrossScanDeduplication || f.Deduper == nil {
		t.Fatalf("OpenDirty did not install cross-scan deduper")
	}
	if f.Deduper != OpenDirtyDeduper(path) {
		t.Fatal("OpenDirty did not share source deduper across reopened scans")
	}
}

func TestRepeatedObservationAddsNoEvidence39243(t *testing.T) {
	d := NewRecordDeduper("OpenDirty").SetSource("dirty.evtx")
	env := eventEnvelope{
		event:       Event{Offset: 0x400, Header: EventHeader{ID: 1}},
		gem:         testGem39243("1"),
		chunkOffset: 0x2000,
	}
	if _, ok := d.Admit(env); !ok {
		t.Fatal("first observation must be admitted")
	}
	for i := 0; i < 2; i++ {
		if _, ok := d.Admit(env); ok {
			t.Fatal("reopened observation must remain deduplicated")
		}
	}
	if d.Count() != 0 {
		t.Fatalf("a rescan of the same coordinate is not a new conflict, got %d evidence", d.Count())
	}
}

func TestDistinctOffsetsKeepDistinctEvidence39243(t *testing.T) {
	d := NewRecordDeduper("OpenDirty")
	first := eventEnvelope{event: Event{Offset: 0x200, Header: EventHeader{ID: 1}}, chunkOffset: 0x1000}
	second := eventEnvelope{event: Event{Offset: 0x400, Header: EventHeader{ID: 1}}, chunkOffset: 0x2000}
	if _, ok := d.Admit(first); !ok {
		t.Fatal("first observation must be admitted")
	}
	if _, ok := d.Admit(second); ok {
		t.Fatal("duplicate identity must be rejected")
	}
	if d.Count() != 1 {
		t.Fatalf("expected one conflict evidence, got %d", d.Count())
	}
	r := d.Rejected()[0]
	if r.AbsoluteOffset != 0x2400 || r.FirstAbsoluteOffset != 0x1200 {
		t.Fatalf("bad source offsets: %+v", r)
	}
}

func TestNewAcceptsTruncatedChunkMagic39243(t *testing.T) {
	header := testHeaderBytes39243(1, 0)
	data := append(header, []byte(ChunkMagic)...)
	data = append(data, make([]byte, 64)...)

	f, err := New(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("truncated but magic-valid chunk should remain recoverable: %v", err)
	}
	if f.Header.ChunkCount != 1 {
		t.Fatalf("chunk count = %d", f.Header.ChunkCount)
	}
}

func TestNewRejectsFullBadChunkMagic39243(t *testing.T) {
	header := testHeaderBytes39243(1, 0)
	chunk := make([]byte, ChunkHeaderSize)
	copy(chunk[0:8], "BADCHNK!")
	data := append(header, chunk...)

	if _, err := New(bytes.NewReader(data)); err == nil {
		t.Fatal("bad chunk signature was accepted")
	}
}

func syntheticDirtyFile39243(t *testing.T, path string, eventIDs ...int64) {
	t.Helper()
	data := make([]byte, 4096+ChunkSize)
	copy(data[0:8], "ElfFile\x00")
	binary.LittleEndian.PutUint64(data[24:32], uint64(len(eventIDs)+1))
	binary.LittleEndian.PutUint16(data[36:38], 1) // MinVersion
	binary.LittleEndian.PutUint16(data[38:40], 2) // MajVersion
	binary.LittleEndian.PutUint16(data[40:42], 4096)
	binary.LittleEndian.PutUint16(data[42:44], 1)
	binary.LittleEndian.PutUint32(data[120:124], 1) // dirty

	chunk := data[4096:]
	copy(chunk[0:8], ChunkMagic)
	binary.LittleEndian.PutUint64(chunk[8:16], 1)
	binary.LittleEndian.PutUint64(chunk[16:24], uint64(len(eventIDs)))
	binary.LittleEndian.PutUint64(chunk[24:32], uint64(eventIDs[0]))
	binary.LittleEndian.PutUint64(chunk[32:40], uint64(eventIDs[len(eventIDs)-1]))
	binary.LittleEndian.PutUint32(chunk[40:44], 128)
	binary.LittleEndian.PutUint32(chunk[44:48], uint32(512+(len(eventIDs)-1)*128))

	// One template definition at chunk-relative 0x900.
	binary.LittleEndian.PutUint32(chunk[384:388], 0x900)
	copy(chunk[0x900:0x904], []byte{0, 0, 0, 0})    // Unknown3
	copy(chunk[0x914:0x918], []byte{8, 0, 0, 0})    // Size
	copy(chunk[0x918:0x91c], []byte{0x0f, 1, 1, 0}) // Fragment header
	chunk[0x91c] = TokenEOF

	for i, id := range eventIDs {
		off := 512 + i*128
		copy(chunk[off:off+4], EventMagic)
		binary.LittleEndian.PutUint32(chunk[off+4:off+8], 128)
		binary.LittleEndian.PutUint64(chunk[off+8:off+16], uint64(id))
		chunk[off+24] = FragmentHeaderToken
		chunk[off+25] = 1
		chunk[off+26] = 1
		chunk[off+28] = TokenTemplateInstance
		binary.LittleEndian.PutUint32(chunk[off+34:off+38], 0x900)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestOpenDirtyCrossScanPublishesEachRecordOnce39243(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dirty-carved.evtx")
	ResetOpenDirtyDeduper(path)
	defer ResetOpenDirtyDeduper(path)

	syntheticDirtyFile39243(t, path, 1, 2)

	count := func() int {
		f, err := OpenDirty(path)
		if err != nil {
			t.Fatalf("OpenDirty: %v", err)
		}
		defer f.Close()
		n := 0
		for event := range f.FastEvents() {
			n++
			if _, ok := event.SourceOffset(); !ok {
				t.Fatal("published event lost its source offset")
			}
		}
		return n
	}

	if got := count(); got != 2 {
		t.Fatalf("first scan published %d events, want 2", got)
	}
	if got := count(); got != 0 {
		t.Fatalf("reopened scan republished %d records, want 0", got)
	}
}

func TestOpenDirtyCrossScanPublishesOnlyNewRecords39243(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dirty-growing.evtx")
	ResetOpenDirtyDeduper(path)
	defer ResetOpenDirtyDeduper(path)

	scan := func() int {
		f, err := OpenDirty(path)
		if err != nil {
			t.Fatalf("OpenDirty: %v", err)
		}
		defer f.Close()
		n := 0
		for range f.FastEvents() {
			n++
		}
		return n
	}

	syntheticDirtyFile39243(t, path, 1, 2)
	if n := scan(); n != 2 {
		t.Fatalf("first scan published %d records, want 2", n)
	}

	// The same source path now exposes an overlapping identity plus one new
	// record. Only the unseen identity may be published.
	syntheticDirtyFile39243(t, path, 2, 3)
	if n := scan(); n != 1 {
		t.Fatalf("rescan published %d records, want only the new record", n)
	}
}

func TestOpenDirtyStructuredChunkSharesFrontier39243(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dirty-structured.evtx")
	ResetOpenDirtyDeduper(path)
	defer ResetOpenDirtyDeduper(path)

	syntheticDirtyFile39243(t, path, 1, 2)
	f, err := OpenDirty(path)
	if err != nil {
		t.Fatalf("OpenDirty: %v", err)
	}
	defer f.Close()

	n := 0
	for range f.FastEvents() {
		n++
	}
	if n != 2 {
		t.Fatalf("stream published %d records, want 2", n)
	}

	chunk, err := f.FetchChunk(4096)
	if err != nil {
		t.Fatalf("FetchChunk: %v", err)
	}
	if chunk.Deduper == nil {
		t.Fatal("structured chunk did not inherit the source frontier")
	}
	n = 0
	for range chunk.Events() {
		n++
	}
	if n != 0 {
		t.Fatalf("structured chunk republished %d records from the previous scan", n)
	}
}

func TestDeduperConcurrent39243(t *testing.T) {
	d := NewRecordDeduper()
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := int64(1); id <= 100; id++ {
				d.AdmitIdentity(RecordIdentity{RecordID: id, ID: id, EventRecordID: id})
			}
		}()
	}
	wg.Wait()
	if d.Seen(1) == false || d.Seen(100) == false {
		t.Fatal("admitted identities not visible")
	}
}
