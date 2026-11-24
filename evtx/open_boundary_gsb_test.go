package evtx_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xrawsec/golang-evtx/evtx"
)

func uid39236Header(chunkCount uint16, chunkOffset uint16) []byte {
	b := make([]byte, binary.Size(evtx.FileHeader{}))
	copy(b[:8], evtx.EvtxMagic+"\x00")
	binary.LittleEndian.PutUint16(b[40:42], chunkOffset)
	binary.LittleEndian.PutUint16(b[42:44], chunkCount)
	return b
}

func TestGSBNewRejectsIncompleteHeaderAndChunkBoundary(t *testing.T) {
	for size := 0; size < binary.Size(evtx.FileHeader{}); size++ {
		raw := uid39236Header(0, 0)[:size]
		if _, err := evtx.New(bytes.NewReader(raw)); err == nil {
			t.Fatalf("header of %d bytes was accepted", size)
		}
	}

	header := uid39236Header(1, uint16(binary.Size(evtx.FileHeader{})))
	if _, err := evtx.New(bytes.NewReader(header)); err == nil {
		t.Fatal("header declaring a missing chunk was accepted")
	}
}

func TestGSBNewAcceptsMinimalHeaderAndCompleteChunk(t *testing.T) {
	minimal := uid39236Header(0, 0)
	f, err := evtx.New(bytes.NewReader(minimal))
	if err != nil {
		t.Fatalf("complete minimal header rejected: %v", err)
	}

	events := 0
	for e := range f.Events() {
		_ = e
		events++
	}
	if events != 0 {
		t.Fatalf("minimal header produced %d events", events)
	}

	offset := uint16(binary.Size(evtx.FileHeader{}))
	complete := append(uid39236Header(1, offset), make([]byte, evtx.ChunkSize)...)
	if _, err := evtx.New(bytes.NewReader(complete)); err != nil {
		t.Fatalf("complete chunk extent rejected: %v", err)
	}
}

func TestGSBOpenRejectsTruncatedFileAndAcceptsMinimalFile(t *testing.T) {
	dir := t.TempDir()

	truncatedPath := filepath.Join(dir, "truncated.evtx")
	if err := os.WriteFile(truncatedPath, uid39236Header(1, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	if f, err := evtx.Open(truncatedPath); err == nil {
		_ = f.Close()
		t.Fatal("Open accepted a file without its declared chunk")
	}

	minimalPath := filepath.Join(dir, "minimal.evtx")
	if err := os.WriteFile(minimalPath, uid39236Header(0, 0), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := evtx.Open(minimalPath)
	if err != nil {
		t.Fatalf("Open rejected complete minimal file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
