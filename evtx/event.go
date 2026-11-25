package evtx

import (
	"bytes"
	"fmt"
	"io"

	"github.com/0xrawsec/golang-utils/log"
)

///////////////////////////////// Event ////////////////////////////////////////

type EventHeader struct {
	Magic     [4]byte
	Size      int32
	ID        int64
	Timestamp FileTime
}

// Validate controls the EventHeader
func (h *EventHeader) Validate() error {
	// Validate the event magic
	if string(h.Magic[:]) != EventMagic {
		return fmt.Errorf("Bad event magic %q", h.Magic)
	}
	// An event cannot be bigger than a Chunk since an event is embedded into a
	// chunk
	if h.Size >= ChunkSize {
		return fmt.Errorf("Too big event")
	}
	// An event cannot be smaller than its header since the event size include the
	// size of the header
	if h.Size < EventHeaderSize {
		return fmt.Errorf("Too small event")
	}
	return nil
}

// Event structure
type Event struct {
	Offset int64 // For debugging purposes
	Header EventHeader
}

// IsValid returns true if the Event is valid
// TODO: find and replace because we now have Validate() method from the header
func (e *Event) IsValid() bool {
	// Validate Magic Header
	return e.Header.Validate() == nil
}

// GoEvtxMap parses the BinXML inside the event and returns a pointer to a
// structure GoEvtxMap
// @c : chunk pointer used for template data already parsed
// return (*GoEvtxMap, error)
func (e Event) GoEvtxMap(c *Chunk) (pge *GoEvtxMap, err error) {
	// An Event can contain only BinXMLFragments
	if !e.IsValid() {
		err = ErrInvalidEvent
		return
	}
	reader := bytes.NewReader(c.Data)
	GoToSeeker(reader, e.Offset+EventHeaderSize)
	// Bug here if we put c
	element, err := Parse(reader, c, false)
	if err != nil && err != io.EOF {
		//panic(err)
		log.Error(err)
	}
	// If not a BinXMLFragment a panic will be raised
	fragment, ok := element.(*Fragment)
	switch {
	case !ok && ModeCarving:
		return
	case !ok:
		// Way to raise panic
		_ = element.(*Fragment)
	}
	return fragment.GoEvtxMap(), err
}

func (e Event) String() string {
	return fmt.Sprintf(
		"Magic: %s\n"+
			"Size: %d\n"+
			"ID: %d\n"+
			"Timestamp: %d\n",
		//"Content: %x",
		e.Header.Magic,
		e.Header.Size,
		e.Header.ID,
		e.Header.Timestamp)
}

// RecordID returns the binary EventRecordID from the event header.
func (h EventHeader) RecordID() int64 { return h.ID }

// EventRecordID mirrors the vocabulary used by the decoded XML event.
func (h EventHeader) EventRecordID() int64 { return h.ID }

// Identity returns the canonical record identity and source coordinates for
// a parsed binary event.
func (e Event) Identity() RecordIdentity {
	return eventEnvelope{event: e}.identity("Event", "")
}

// RecordIdentity is an alias for Identity.
func (e Event) RecordIdentity() RecordIdentity { return e.Identity() }

// RecordID returns the canonical binary record id.
func (e Event) RecordID() int64 { return e.Header.ID }

// EventRecordID returns the header EventRecordID. The decoded GoEvtxMap value
// can differ only for malformed/tampered records; the stream deduper records
// both values in its evidence.
func (e Event) EventRecordID() int64 { return e.Header.ID }

// SameRecordIdentity reports whether two binary events claim the same
// non-zero EventRecordID.
func (e Event) SameRecordIdentity(other Event) bool {
	return e.Header.ID != 0 && e.Header.ID == other.Header.ID
}
