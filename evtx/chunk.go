package evtx

import (
	"bytes"
	"fmt"
	"io"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/encoding"
	"github.com/0xrawsec/golang-utils/log"
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
	// Carving makes parsing tolerant for a single chunk recovered from a
	// dirty/truncated source. It is independent from the process-wide
	// ModeCarving switch so OpenDirty can recover a chunk while ordinary
	// opens keep their historical fail-fast behaviour.
	Carving bool
	// Deduper, when set, is the source-level identity frontier a structured
	// chunk consumer must share with the File event streams. A nil value keeps
	// Chunk.Events local to the chunk.
	Deduper *RecordDeduper
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
	if c.Header.NumFirstRecLog != other.Header.NumFirstRecLog {
		return c.Header.NumFirstRecLog < other.Header.NumFirstRecLog
	}
	return c.Offset < other.Offset
}

// ParseStringTable parses the string table located at the current offset in the
// reader and modify the chunk object
// @reader : reader object to parse string table from
func (c *Chunk) ParseStringTable(reader io.ReadSeeker) {
	if c.StringTable == nil {
		c.StringTable = make(ChunkStringTable)
	}
	strOffset := int32(0)
	for i := int64(0); i < sizeStringBucket*4; i += 4 {
		if err := encoding.Unmarshal(reader, &strOffset, Endianness); err != nil {
			// The string bucket itself is truncated. No string entry can be
			// recovered from this point; the caller may still recover event
			// offsets from the fixed table boundary.
			return
		}
		if strOffset > 0 {
			cs, err := StringAt(reader, int64(strOffset))
			if err != nil {
				if !ModeCarving && !c.Carving {
					panic(err)
				}
				continue
			}
			c.StringTable[strOffset] = cs
		}
	}
}

// ParseTemplaTable parses the template table located at the current offset in
// the reader passed as parameter and modifies the current Chunk object
// @reader : reader object to parse string table from
func (c *Chunk) ParseTemplateTable(reader io.ReadSeeker) error {
	if c.TemplateTable == nil {
		c.TemplateTable = make(TemplateTable)
	}
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
			if ModeCarving || c.Carving {
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
	if offset < 0 || offset+EventHeaderSize > int64(len(c.Data)) {
		return
	}
	// OffsetLastRec is the parser's upper bound. Manually constructed and
	// truncated chunks may leave it zero; the Data bounds above are then the
	// authoritative limit.
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

// Events returns a channel of *GoEvtxMap
// return (chan *GoEvtxMap)
func (c *Chunk) Events() (cgem chan *GoEvtxMap) {
	// Unbuffered Event channel
	cgem = make(chan *GoEvtxMap, len(c.EventOffsets))
	d := c.Deduper
	if d == nil {
		d = NewRecordDeduper("Chunk.Events")
	}
	go func() {
		defer close(cgem)
		for env := range c.parsedEvents() {
			if _, ok := d.Admit(env); ok {
				cgem <- env.gem
			}
		}
	}()
	return
}

// parsedEvents emits every successfully decoded event together with its
// binary/source coordinates. File-level streams use the envelope so identity
// decisions can be made across chunks and scans.
func (c *Chunk) parsedEvents() <-chan eventEnvelope {
	cec := make(chan eventEnvelope, len(c.EventOffsets))
	go func() {
		defer close(cec)
		if c.TemplateTable == nil {
			c.TemplateTable = make(TemplateTable)
		}
		for _, eo := range c.EventOffsets {
			env, ok := c.parseEnvelope(int64(eo))
			if !ok {
				continue
			}
			env.annotate()
			cec <- env
		}
	}()
	return cec
}

// parseEnvelope parses one event offset and returns false when the record is
// incomplete or cannot be decoded. Recovering a truncated chunk must publish
// the complete records that precede the cut without letting a partial trailing
// record panic the whole public event stream.
func (c *Chunk) parseEnvelope(offset int64) (env eventEnvelope, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	event := c.ParseEvent(offset)
	if event.Header.Validate() != nil {
		return eventEnvelope{}, false
	}
	// A truncated trailing record has a valid-looking header but not enough
	// bytes for its declared payload. Do not feed that partial record to the
	// BinXML parser.
	if offset+int64(event.Header.Size) > int64(len(c.Data)) {
		return eventEnvelope{}, false
	}
	gem, err := event.GoEvtxMap(c)
	if err != nil || gem == nil {
		return eventEnvelope{}, false
	}
	return eventEnvelope{
		event:       event,
		gem:         gem,
		chunkOffset: c.Offset,
	}, true
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
