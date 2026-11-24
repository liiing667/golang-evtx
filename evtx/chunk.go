package evtx

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/encoding"
	"github.com/0xrawsec/golang-utils/log"
)

var (
	// ErrEventCountMismatch is returned when the number of events which can be
	// published from a chunk does not match the count declared in its header.
	ErrEventCountMismatch = errors.New("chunk event count does not match the complete record set")
)

// ChunkString is similare to BinXMLName
type ChunkString struct {
	Name
}

// StringAt : utility function to get a ChunkString object at a given offset
// @reader : reader containing ChunkString struct @ offset
// @offset : offset at which we find the ChunkString
// return ChunkString
func StringAt(reader io.ReadSeeker, offset int64) (cs ChunkString, err error) {
	// Backup offset
	backup := BackupSeeker(reader)
	// Offsets are relative to start of chunk
	GoToSeeker(reader, offset)
	err = cs.Parse(reader)
	/*if err != nil {
		return
	}*/
	GoToSeeker(reader, backup)
	return
}

// ChunkStringTable definition
type ChunkStringTable map[int32]ChunkString

// TemplateTable definition
type TemplateTable map[int32]TemplateDefinitionData

/////////////////////////////// ChunkHeader ////////////////////////////////////

// ChunkHeader  structure definition
type ChunkHeader struct {
	Magic           [8]byte
	NumFirstRecLog  int64
	NumLastRecLog   int64
	FirstEventRecID int64
	LastEventRecID  int64
	SizeHeader      int32
	OffsetLastRec   int32
	Freespace       int32
	CheckSum        uint32
}

// Validate controls the validity of the chunk header
func (ch *ChunkHeader) Validate() error {
	if string(ch.Magic[:]) != ChunkMagic {
		return fmt.Errorf("Invalid chunk magic: %q", ch.Magic)
	}
	if ch.SizeHeader != 128 {
		return fmt.Errorf("Invalid chunk header size: %d instead of 128", ch.SizeHeader)
	}
	if ch.OffsetLastRec >= ChunkSize {
		return fmt.Errorf("Last event offset exceed size of chunk")
	}
	return nil
}

func (ch ChunkHeader) String() string {
	return fmt.Sprintf(
		"\tMagic: %s\n"+
			"\tNumFirstRecLog: %d\n"+
			"\tNumLastRecLog: %d\n"+
			"\tNumFirstRecFile: %d\n"+
			"\tNumLastRecFile: %d\n"+
			"\tSizeHeader: %d\n"+
			"\tOffsetLastRec: %d\n"+
			"\tFreespace: %d\n"+
			"\tCheckSum: 0x%08x\n",
		ch.Magic,
		ch.NumFirstRecLog,
		ch.NumLastRecLog,
		ch.FirstEventRecID,
		ch.LastEventRecID,
		ch.SizeHeader,
		ch.OffsetLastRec,
		ch.Freespace,
		ch.CheckSum)
}

//////////////////////////////////// Chunk /////////////////////////////////////

// Chunk structure definition
type Chunk struct {
	Offset        int64
	Header        ChunkHeader
	StringTable   ChunkStringTable
	TemplateTable TemplateTable
	EventOffsets  []int32
	Data          []byte
}

// NewChunk initialize and returns a new Chunk structure
// return Chunk
func NewChunk() Chunk {
	return Chunk{StringTable: make(ChunkStringTable, 0), TemplateTable: make(TemplateTable, 0)}
}

// ParseChunkHeader parses a chunk header at offset
func (c *Chunk) ParseChunkHeader(reader io.ReadSeeker) {
	err := encoding.Unmarshal(reader, &c.Header, Endianness)
	if err != nil {
		panic(err)
	}
}

// Less implement datastructs.Sortable
func (c Chunk) Less(s datastructs.Sortable) bool {
	other := s.(Chunk)
	return c.Header.NumFirstRecLog < other.Header.NumFirstRecLog
}

// ParseStringTable parses the string table located at the current offset in the
// reader and modify the chunk object
// @reader : reader object to parse string table from
func (c *Chunk) ParseStringTable(reader io.ReadSeeker) {
	strOffset := int32(0)
	for i := int64(0); i < sizeStringBucket*4; i += 4 {
		encoding.Unmarshal(reader, &strOffset, Endianness)
		if strOffset > 0 {
			cs, err := StringAt(reader, int64(strOffset))
			if err != nil {
				if !ModeCarving {
					panic(err)
				}
			}
			c.StringTable[strOffset] = cs
		}
	}
	return
}

// ParseTemplaTable parses the template table located at the current offset in
// the reader passed as parameter and modifies the current Chunk object
// @reader : reader object to parse string table from
func (c *Chunk) ParseTemplateTable(reader io.ReadSeeker) error {
	templateDataOffset := int32(0)
	for i := int32(0); i < sizeTemplateBucket*4; i = i + 4 {
		//parse(buf, i, &tempOffsetTable[j])
		err := encoding.Unmarshal(reader, &templateDataOffset, Endianness)
		if err != nil {
			// panic(err)
			log.DebugDontPanic(err)
			return err
		}
		if templateDataOffset > 0 {
			backup := BackupSeeker(reader)
			// We arrive in template data, we have to do some offset patching in order to get
			// back to TemplateInstance token and make it easily parsable by binxml.Parse
			GoToSeeker(reader, int64(templateDataOffset))
			tdd := TemplateDefinitionData{}
			err := tdd.Parse(reader)
			if err != nil {
				//panic(err)
				log.DebugDontPanic(err)
				return err
			}
			c.TemplateTable[templateDataOffset] = tdd
			GoToSeeker(reader, backup)
		}
	}
	return nil
}

// ParseEventOffsets parses the offsets at which we can find the events and
// modifies the current Chunk object
// @reader : reader object to parse event offsets from
func (c *Chunk) ParseEventOffsets(reader io.ReadSeeker) (err error) {
	c.EventOffsets = make([]int32, 0)
	offsetEvent := int32(BackupSeeker(reader))
	c.EventOffsets = append(c.EventOffsets, offsetEvent)
	for offsetEvent <= c.Header.OffsetLastRec {
		eh := EventHeader{}
		GoToSeeker(reader, int64(offsetEvent))
		if err = encoding.Unmarshal(reader, &eh, Endianness); err != nil {
			log.DebugDontPanic(err)
			return err
		}
		// Event Header is not valid
		if err = eh.Validate(); err != nil {
			// we bruteforce in carving mode
			if ModeCarving {
				offsetEvent++
				continue
			}
			return err
		}
		offsetEvent += eh.Size
		c.EventOffsets = append(c.EventOffsets, offsetEvent)
	}
	return nil
}

// ParseEvent parses an Event from the current chunk located at the relative
// offset in c.Data, does not alter the current Chunk structure
// @offset : offset to parse the Event at
// return Event : parsed Event
func (c *Chunk) ParseEvent(offset int64) (e Event) {
	if offset < 0 || offset >= int64(len(c.Data)) {
		return
	}
	// OffsetLastRec is the parser's upper bound. Manually constructed test
	// chunks may leave it zero; in that case the backing Data bounds above are
	// sufficient.
	if c.Header.OffsetLastRec > 0 && int64(c.Header.OffsetLastRec) < offset {
		return
	}
	reader := bytes.NewReader(c.Data)
	GoToSeeker(reader, offset)
	e.Offset = offset
	err := encoding.Unmarshal(reader, &e.Header, Endianness)
	if err != nil {
		panic(err)
	}
	/*err := encoding.Unmarshal(reader, &e.Magic, Endianness)
	if err != nil {
		panic(err)
	}
	err = encoding.Unmarshal(reader, &e.Size, Endianness)
	if err != nil {
		panic(err)
	}
	err = encoding.Unmarshal(reader, &e.ID, Endianness)
	if err != nil {
		panic(err)
	}
	err = encoding.Unmarshal(reader, &e.Timestamp, Endianness)
	if err != nil {
		panic(err)
	}*/
	return e
}

// declaredEventCount returns the inclusive number of records declared by the
// chunk header. The second return value is false when the header does not
// contain a usable declaration (for example a manually constructed chunk).
// A negative count marks an internally inconsistent declaration.
func (c Chunk) declaredEventCount() (int, bool) {
	countFor := func(first, last int64) (int, bool, bool) {
		// A zero/zero range is the unset value of the header fields. An empty
		// chunk is handled naturally because it has no publishable event.
		if first == 0 && last == 0 {
			return 0, false, true
		}
		// Empty chunks use -1 as the terminal record number/identifier. Some
		// headers encode the log range as first=1,last=-1 while the record IDs
		// are both -1.
		if last == -1 {
			return 0, true, true
		}
		if first < 0 || last < first {
			return -1, true, false
		}
		span := last - first
		if span == math.MaxInt64 {
			return -1, true, false
		}
		return int(span + 1), true, true
	}

	recordCount, recordSet, recordValid := countFor(c.Header.FirstEventRecID, c.Header.LastEventRecID)
	logCount, logSet, logValid := countFor(c.Header.NumFirstRecLog, c.Header.NumLastRecLog)

	if (recordSet && !recordValid) || (logSet && !logValid) {
		return -1, true
	}

	switch {
	case recordSet && logSet:
		if recordCount != logCount {
			return -1, true
		}
		return recordCount, true
	case recordSet:
		return recordCount, true
	case logSet:
		return logCount, true
	default:
		return 0, false
	}
}

// EventCount returns the event count declared by the chunk header. When the
// header has no explicit first/last record pair, it falls back to the number of
// parsed offsets. An inconsistent header is reported as -1.
func (c Chunk) EventCount() int {
	if count, ok := c.declaredEventCount(); ok {
		return count
	}
	return len(c.EventOffsets)
}

// ValidateEventCount checks that actual is the complete record count declared
// by the chunk. Chunks without an explicit header declaration remain accepted
// for compatibility with manually constructed chunks.
func (c Chunk) ValidateEventCount(actual int) error {
	expected, enforced := c.declaredEventCount()
	if !enforced {
		return nil
	}
	if actual != expected {
		return fmt.Errorf("%w: declared %d, actual %d", ErrEventCountMismatch, expected, actual)
	}
	return nil
}

// countEventOffsets returns the offsets expected to address complete records.
// It accepts either one offset per declared record or the historical parser
// representation with one additional boundary offset after OffsetLastRec.
func (c Chunk) countEventOffsets(expected int) ([]int32, error) {
	offsets := c.EventOffsets
	if expected == 0 {
		// An empty chunk may retain the historical initial/boundary offset.
		// Publication must contain no records regardless of that bookkeeping.
		return []int32{}, nil
	}
	if len(offsets) == expected {
		return offsets, nil
	}

	if len(offsets) == expected+1 && expected > 0 {
		last := offsets[len(offsets)-1]
		if c.Header.OffsetLastRec > 0 && int64(last) > int64(c.Header.OffsetLastRec) {
			return offsets[:expected], nil
		}
	}

	return nil, fmt.Errorf("%w: declared %d, offsets %d", ErrEventCountMismatch, expected, len(offsets))
}

// eventMapAtOffset converts one offset and turns a malformed record into no
// publishable event instead of crashing the consumer goroutine.
func (c *Chunk) eventMapAtOffset(offset int32) (gem *GoEvtxMap) {
	defer func() {
		if r := recover(); r != nil {
			log.DebugDontPanic(r)
			gem = nil
		}
	}()

	event := c.ParseEvent(int64(offset))
	gem, err := event.GoEvtxMap(c)
	if err != nil || gem == nil {
		return nil
	}
	return gem
}

// Events returns a channel of *GoEvtxMap.
//
// A chunk is an atomic publication unit: records are parsed before anything is
// sent to the returned channel. When the chunk header declares a count and the
// complete parseable record set does not match that count, no partial prefix is
// published. Legitimate empty chunks and chunks whose parsed record count matches
// the header are emitted unchanged.
func (c *Chunk) Events() (cgem chan *GoEvtxMap) {
	cgem = make(chan *GoEvtxMap, len(c.EventOffsets))
	go func() {
		defer close(cgem)

		expectedCount, enforceCount := c.declaredEventCount()

		offsets := c.EventOffsets
		if enforceCount {
			completeOffsets, err := c.countEventOffsets(expectedCount)
			if err != nil {
				log.Warnf("dropping inconsistent chunk at offset %d: %s", c.Offset, err)
				return
			}
			offsets = completeOffsets
		}

		events := make([]*GoEvtxMap, 0, len(c.EventOffsets))
		for _, eo := range offsets {
			// For every event offset, parse the event at that position. Malformed
			// trailing offsets are skipped here; the count validation below decides
			// whether the whole chunk is a complete record set.
			if gem := c.eventMapAtOffset(eo); gem != nil {
				events = append(events, gem)
			}
		}

		if enforceCount {
			if err := c.ValidateEventCount(len(events)); err != nil {
				log.Warnf("dropping inconsistent chunk at offset %d: %s", c.Offset, err)
				return
			}
		}

		for _, gem := range events {
			cgem <- gem
		}
	}()
	return cgem
}

func (c Chunk) String() string {
	templateOffsets := make([]int32, len(c.TemplateTable))
	i := 0
	for to := range c.TemplateTable {
		templateOffsets[i] = to
		i++
	}
	return fmt.Sprintf(
		"Header: %v\n"+
			"StringTable: %v\n"+
			"TemplateTable: %v\n"+
			"EventOffsets: %v\n"+
			"TemplatesOffsets (for debug): %v\n", c.Header, c.StringTable, c.TemplateTable, c.EventOffsets, templateOffsets)
}
