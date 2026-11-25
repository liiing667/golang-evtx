package evtx

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/encoding"
	"github.com/0xrawsec/golang-utils/log"
)

// ChunkCache structure as a Set
type ChunkCache struct {
	datastructs.SyncedSet
}

/////////////////////////////// ChunkSorter ////////////////////////////////////

// ChunkSorter structure used to sort chunks before parsing the events inside
// prevent unordered events
type ChunkSorter []Chunk

// Implement Sortable interface
func (cs ChunkSorter) Len() int {
	return len(cs)
}

// Implement Sortable interface
func (cs ChunkSorter) Less(i, j int) bool {
	if cs[i].Header.NumFirstRecLog != cs[j].Header.NumFirstRecLog {
		return cs[i].Header.NumFirstRecLog < cs[j].Header.NumFirstRecLog
	}
	// Deterministic source order for reused/dirty chunk generations.
	return cs[i].Offset < cs[j].Offset
}

// Implement Sortable interface
func (cs ChunkSorter) Swap(i, j int) {
	cs[i], cs[j] = cs[j], cs[i]
}

//////////////////////////////////// File //////////////////////////////////////

var (
	ErrCorruptedHeader = fmt.Errorf("Corrupted header")
	ErrDirtyFile       = fmt.Errorf("File is flagged as dirty")
	ErrRepairFailed    = fmt.Errorf("File header could not be repaired")
)

// FileHeader structure definition
type FileHeader struct {
	Magic           [8]byte
	FirstChunkNum   uint64
	LastChunkNum    uint64
	NextRecordID    uint64
	HeaderSpace     uint32
	MinVersion      uint16
	MajVersion      uint16
	ChunkDataOffset uint16
	ChunkCount      uint16
	Unknown         [76]byte
	Flags           uint32
	CheckSum        uint32
}

func (f *FileHeader) Verify() error {
	if !bytes.Equal(f.Magic[:], []byte("ElfFile\x00")) {
		return ErrCorruptedHeader
	}
	// File is dirty
	if f.Flags == 1 {
		return ErrDirtyFile
	}
	return nil
}

// Repair the header. It makes sense to use this function
// whenever the file is flagged as dirty
func (f *FileHeader) Repair(r io.ReadSeeker) error {
	chunkHeaderRE := regexp.MustCompile(ChunkMagic)
	rr := bufio.NewReader(r)
	cc := uint16(0)
	for loc := chunkHeaderRE.FindReaderIndex(rr); loc != nil; loc = chunkHeaderRE.FindReaderIndex(rr) {
		cc++
	}

	if f.ChunkCount > cc {
		return ErrRepairFailed
	}

	// Fixing chunk count
	f.ChunkCount = cc
	// Fixing LastChunkNum
	if f.ChunkCount > 0 {
		f.LastChunkNum = uint64(f.ChunkCount - 1)
	} else {
		f.LastChunkNum = 0
	}
	// File is not dirty anymore
	f.Flags = 0
	return nil
}

// File structure definition
type File struct {
	sync.Mutex      // We need it if we want to parse (read) chunks in several threads
	Header          FileHeader
	file            io.ReadSeeker
	path            string
	monitorExisting bool

	dedupMu                sync.Mutex
	Deduper                *RecordDeduper
	CrossScanDeduplication bool
	truncatedRecovery      bool
}

// New EvtxFile structure initialized from an open buffer
// @r : buffer containing evtx data to parse
// return File : File structure initialized
func New(r io.ReadSeeker) (ef File, err error) {
	if r == nil {
		return ef, ErrCorruptedHeader
	}
	ef.file = r
	if f, ok := r.(*os.File); ok {
		ef.path = f.Name()
	}
	if err = ef.parseFileHeader(); err != nil {
		return ef, err
	}
	if !bytes.Equal(ef.Header.Magic[:], []byte("ElfFile\x00")) {
		return ef, ErrCorruptedHeader
	}
	// A dirty log is by definition mid-write; let OpenDirty repair its header
	// and recover whatever complete chunks remain instead of rejecting it at
	// the admission boundary.
	if ef.Header.Flags != 1 {
		if err = ef.validateAvailableChunkMagics(); err != nil {
			return ef, err
		}
	}
	return
}

// validateAvailableChunkMagics rejects a fully readable chunk header carrying
// a non-zero but invalid signature. Short/truncated and zero-filled chunk
// prefixes are left for recovery/carving paths so ordinary truncated chunks
// remain readable.
func (ef *File) validateAvailableChunkMagics() error {
	if ef.file == nil {
		return nil
	}

	current, err := ef.file.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	defer ef.file.Seek(current, io.SeekStart)

	for i := uint16(0); i < ef.Header.ChunkCount; i++ {
		offset := int64(ef.Header.ChunkDataOffset) + int64(ChunkSize)*int64(i)
		if _, err := ef.file.Seek(offset, io.SeekStart); err != nil {
			continue
		}

		magic := make([]byte, 8)
		if _, err := io.ReadFull(ef.file, magic); err != nil {
			// A truncated chunk is a supported recovery case.
			continue
		}
		if bytes.Equal(magic, make([]byte, 8)) {
			continue
		}
		if string(magic) != ChunkMagic {
			return fmt.Errorf("%w: invalid chunk magic at offset %d", ErrCorruptedHeader, offset)
		}
	}
	return nil
}

// New EvtxFile structure initialized from file
// @filepath : filepath of the evtx file to parse
// return File : File structure initialized
func Open(filepath string) (ef File, err error) {
	file, err := os.Open(filepath)
	if err != nil {
		return
	}
	ef.path = filepath

	ef, err = New(file)
	if err != nil {
		file.Close()
		return
	}

	err = ef.Header.Verify()

	return
}

// OpenDirty is a wrapper around Open to handle the case
// where the file opened has its dirty flag set
func OpenDirty(filepath string) (ef File, err error) {
	// Repair the file header if file is dirty
	if ef, err = Open(filepath); err == ErrDirtyFile {
		err = ef.Header.Repair(ef.file)
	}
	if err != nil && err != ErrDirtyFile {
		if ef.file != nil {
			if closer, ok := ef.file.(io.Closer); ok {
				_ = closer.Close()
			}
		}
		return
	}

	// OpenDirty is the public entry point used by recovery/carving
	// consumers. Share one identity frontier across repeated scans and
	// reopened handles for the same file generation. Truncated chunk
	// recovery remains enabled; identity deduplication never removes bytes.
	ef.path = filepath
	ef.CrossScanDeduplication = true
	ef.truncatedRecovery = true
	ef.Deduper = OpenDirtyDeduper(filepath)
	return
}

// Reopen discards the current reader and parse position and reopens the file
// from its path. The cross-scan identity frontier of an OpenDirty consumer is
// retained, so a reopened scan does not republish records already observed in
// this file generation. Environment files without a path are rewound instead.
func (ef *File) Reopen() error {
	ef.Lock()
	path := ef.path
	var newFile *os.File
	var err error
	if path != "" {
		newFile, err = os.Open(path)
		if err != nil {
			ef.Unlock()
			return err
		}
	}
	old := ef.file
	if newFile != nil {
		ef.file = newFile
	}
	ef.Header = FileHeader{}
	if ef.file == nil {
		ef.Unlock()
		return io.EOF
	}
	GoToSeeker(ef.file, 0)
	err = encoding.Unmarshal(ef.file, &ef.Header, Endianness)
	if err == nil && ef.Header.Flags == 1 {
		if repairErr := ef.Header.Repair(ef.file); repairErr != nil {
			err = repairErr
		}
	}
	ef.Unlock()

	if newFile != nil && old != nil && old != newFile {
		if closer, ok := old.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	ef.dedupMu.Lock()
	if ef.CrossScanDeduplication && ef.Deduper == nil && path != "" {
		ef.Deduper = OpenDirtyDeduper(path)
	}
	ef.dedupMu.Unlock()
	return err
}

// Reset rewinds the reader and reloads the committed file header while keeping
// the same File and its cross-scan identity state.
func (ef *File) Reset() error {
	return ef.Reopen()
}

// Path returns the path used to open the File, if any.
func (ef *File) Path() string {
	ef.Lock()
	defer ef.Unlock()
	return ef.path
}

// SetMonitorExisting sets monitorExisting flag of EvtxFile struct in order to
// return already existing events when using MonitorEvents
func (ef *File) SetMonitorExisting(value bool) {
	ef.monitorExisting = value
}

// ParseFileHeader parses a the file header of the file structure and modifies
// the Header of the current structure
func (ef *File) ParseFileHeader() {
	if err := ef.parseFileHeader(); err != nil {
		panic(err)
	}
}

// parseFileHeader reloads the file header and returns read/decoding errors
// instead of panicking. Public ParseFileHeader keeps its historical panic
// behaviour for callers that depend on it.
func (ef *File) parseFileHeader() error {
	ef.Lock()
	defer ef.Unlock()

	if ef.file == nil {
		return io.EOF
	}
	GoToSeeker(ef.file, 0)
	ef.Header = FileHeader{}
	err := encoding.Unmarshal(ef.file, &ef.Header, Endianness)
	return err
}

func (fh FileHeader) String() string {
	return fmt.Sprintf(
		"Magic: %q\n"+
			"FirstChunkNum: %d\n"+
			"LastChunkNum: %d\n"+
			"NumNextRecord: %d\n"+
			"HeaderSpace: %d\n"+
			"MinVersion: 0x%04x\n"+
			"MaxVersion: 0x%04x\n"+
			"SizeHeader: %d\n"+
			"ChunkCount: %d\n"+
			"Flags: 0x%08x\n"+
			"CheckSum: 0x%08x\n",
		fh.Magic,
		fh.FirstChunkNum,
		fh.LastChunkNum,
		fh.NextRecordID,
		fh.HeaderSpace,
		fh.MinVersion,
		fh.MajVersion,
		fh.ChunkDataOffset,
		fh.ChunkCount,
		fh.Flags,
		fh.CheckSum)

}

// FetchRawChunk fetches a raw Chunk (without parsing String and Template tables)
// @offset : offset in the current file where to find the Chunk
// return Chunk : Chunk (raw) parsed
func (ef *File) FetchRawChunk(offset int64) (Chunk, error) {
	ef.Lock()
	defer ef.Unlock()
	c := NewChunk()
	c.Carving = ef.truncatedRecovery
	if ef.CrossScanDeduplication {
		ef.dedupMu.Lock()
		c.Deduper = ef.Deduper
		ef.dedupMu.Unlock()
	}
	GoToSeeker(ef.file, offset)
	c.Offset = offset
	c.Data = make([]byte, ChunkHeaderSize)
	n, err := ef.file.Read(c.Data)
	if err != nil && n == 0 {
		return c, err
	}
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return c, err
	}
	reader := bytes.NewReader(c.Data)
	c.ParseChunkHeader(reader)
	return c, nil
}

// FetchChunk fetches a Chunk
// @offset : offset in the current file where to find the Chunk
// return Chunk : Chunk parsed
func (ef *File) FetchChunk(offset int64) (Chunk, error) {
	ef.Lock()
	defer ef.Unlock()
	c := NewChunk()
	c.Carving = ef.truncatedRecovery
	if ef.CrossScanDeduplication {
		ef.dedupMu.Lock()
		c.Deduper = ef.Deduper
		ef.dedupMu.Unlock()
	}
	GoToSeeker(ef.file, offset)
	c.Offset = offset
	c.Data = make([]byte, ChunkSize)
	n, readErr := io.ReadFull(ef.file, c.Data)
	if readErr != nil && n == 0 {
		return c, readErr
	}
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return c, readErr
	}
	if n < ChunkHeaderSize {
		return c, io.ErrUnexpectedEOF
	}
	// Keep only the bytes actually present so a partial trailing record is
	// rejected by the parser bounds instead of being decoded from zero
	// padding.
	c.Data = c.Data[:n]
	reader := bytes.NewReader(c.Data)
	c.ParseChunkHeader(reader)
	// Go to after Header
	stringTableStart := int64(c.Header.SizeHeader)
	if stringTableStart < ChunkHeaderSize {
		stringTableStart = ChunkHeaderSize
	}
	if stringTableStart > ChunkSize {
		stringTableStart = ChunkHeaderSize
	}
	stringTableEnd := stringTableStart + int64(sizeStringBucket)*4
	eventOffsetsStart := stringTableEnd + int64(sizeTemplateBucket)*4
	if eventOffsetsStart > ChunkSize {
		// A malformed/truncated chunk cannot provide a valid table boundary.
		// Leave the default event offset list empty rather than seeking into
		// an unrelated region of the chunk data.
		eventOffsetsStart = ChunkSize
	}
	GoToSeeker(reader, stringTableStart)
	c.ParseStringTable(reader)
	GoToSeeker(reader, stringTableEnd)
	templateErr := c.ParseTemplateTable(reader)

	// Event offsets live at a fixed table boundary. Seeking there explicitly
	// keeps truncated/template-damaged chunks recoverable instead of letting a
	// short template parse move the event cursor.
	GoToSeeker(reader, eventOffsetsStart)
	offsetErr := c.ParseEventOffsets(reader)

	if templateErr != nil {
		return c, templateErr
	}
	if offsetErr != nil {
		return c, offsetErr
	}
	return c, nil
}

// Chunks returns a chan of all the Chunks found in the current file
// return (chan Chunk)
func (ef *File) Chunks() (cc chan Chunk) {
	ss := datastructs.NewSortedSlice(0, int(ef.Header.ChunkCount))
	cc = make(chan Chunk)
	go func() {
		defer close(cc)
		for i := uint16(0); i < ef.Header.ChunkCount; i++ {
			offsetChunk := int64(ef.Header.ChunkDataOffset) + int64(ChunkSize)*int64(i)
			chunk, err := ef.FetchRawChunk(offsetChunk)
			switch {
			case err != nil && err != io.EOF:
				panic(err)
			case err == nil:
				ss.Insert(chunk)
			}
		}
		// sorted slice has to be iterated backward
		for rc := range ss.ReversedIter() {
			cc <- rc.(Chunk)
		}
	}()
	return
}

// UnorderedChunks returns a chan of all the Chunks found in the current file
// return (chan Chunk)
func (ef *File) UnorderedChunks() (cc chan Chunk) {
	cc = make(chan Chunk)
	go func() {
		defer close(cc)
		for i := uint16(0); i < ef.Header.ChunkCount; i++ {
			offsetChunk := int64(ef.Header.ChunkDataOffset) + int64(ChunkSize)*int64(i)
			//chunk, err := ef.FetchChunk(offsetChunk)
			chunk, err := ef.FetchRawChunk(offsetChunk)
			switch {
			case err != nil && err != io.EOF:
				panic(err)
			case err == nil:
				cc <- chunk
			}
		}
	}()
	return
}

// monitorChunks returns a chan of the new Chunks found in the file under
// monitoring created after the monitoring started
// @stop: a channel used to stop the monitoring if needed
// @sleep: sleep time
// return (chan Chunk)
func (ef *File) monitorChunks(stop chan bool, sleep time.Duration) (cc chan Chunk) {
	cc = make(chan Chunk, 4)
	sleepTime := sleep
	markedChunks := datastructs.NewSyncedSet()

	// Main routine to feed the Chunk Channel
	go func() {
		defer close(cc)
		firstLoopFlag := !ef.monitorExisting
		for {
			// Parse the file header again to get the updates in the file
			ef.ParseFileHeader()

			// check if we should stop or not
			select {
			case <-stop:
				return
			default:
				// go through
			}
			curChunks := datastructs.NewSyncedSet()
			//cs := make(ChunkSorter, 0, ef.Header.ChunkCount)
			ss := datastructs.NewSortedSlice(0, int(ef.Header.ChunkCount))
			for i := uint16(0); i < ef.Header.ChunkCount; i++ {
				offsetChunk := int64(ef.Header.ChunkDataOffset) + int64(ChunkSize)*int64(i)
				chunk, err := ef.FetchRawChunk(offsetChunk)
				curChunks.Add(chunk.Header.FirstEventRecID, chunk.Header.LastEventRecID)
				// We append only the Chunks whose EventRecordIds have not been treated yet
				if markedChunks.Contains(chunk.Header.FirstEventRecID) && markedChunks.Contains(chunk.Header.LastEventRecID) {
					continue
				}
				switch {
				case err != nil && err != io.EOF:
					panic(err)
				case err == nil:
					markedChunks.Add(chunk.Header.FirstEventRecID)
					markedChunks.Add(chunk.Header.LastEventRecID)
					if !firstLoopFlag {
						//cs = append(cs, chunk)
						ss.Insert(chunk)
					}
				}
			}

			// Cleanup the useless cache entries (consider putting in go routine if worth)
			markedChunks = datastructs.NewSyncedSet(markedChunks.Intersect(curChunks))

			// We flag out of first loop
			firstLoopFlag = false
			// We sort out the chunks
			//sort.Stable(cs)
			//for _, rc := range cs {
			for rc := range ss.ReversedIter() {
				chunk, err := ef.FetchChunk(rc.(Chunk).Offset)
				switch {
				case err != nil && err != io.EOF && !ef.truncatedRecovery:
					panic(err)
				case err == nil || len(chunk.EventOffsets) > 0:
					cc <- chunk
				}
			}

			// Check if we should quit
			if ef.Header.ChunkCount >= math.MaxUint16 {
				log.Info("Monitoring stopped: maximum chunk number reached")
				break
			}

			// Sleep between loops
			time.Sleep(sleepTime)
		}
	}()
	return
}

// Events returns a chan pointers to all the GoEvtxMap found in the current file
// this is a slow implementation, FastEvents should be prefered
// return (chan *GoEvtxMap)
func (ef *File) Events() (cgem chan *GoEvtxMap) {
	cgem = make(chan *GoEvtxMap, 1)
	d := ef.scanDeduper("Events")
	go func() {
		defer close(cgem)
		for c := range ef.Chunks() {
			cpc, err := ef.FetchChunk(c.Offset)
			ec, ok := ef.chunkEnvelopes(cpc, err)
			if !ok {
				continue
			}
			for env := range ec {
				if _, admit := d.Admit(env); admit {
					cgem <- env.gem
				}
			}
		}
	}()
	return
}

// FastEvents returns a chan pointers to all the GoEvtxMap found in the current
// file. Same as Events method but the fast version
// return (chan *GoEvtxMap)
func (ef *File) FastEvents() (cgem chan *GoEvtxMap) {
	cgem = make(chan *GoEvtxMap, 42)
	d := ef.scanDeduper("FastEvents")
	go func() {
		defer close(cgem)
		chanQueue := make(chan (<-chan eventEnvelope), MaxJobs)
		go func() {
			defer close(chanQueue)
			for pc := range ef.Chunks() {
				cpc, err := ef.FetchChunk(pc.Offset)
				ec, ok := ef.chunkEnvelopes(cpc, err)
				if ok {
					chanQueue <- ec
				}
			}
		}()
		for ec := range chanQueue {
			for env := range ec {
				log.Debug(env.gem)
				if _, admit := d.Admit(env); admit {
					cgem <- env.gem
				}
			}
		}
	}()
	return
}

// UnorderedEvents returns a chan pointers to all the GoEvtxMap found in the current
// file. Same as FastEvents method but the order by time is not guaranteed. It can
// significantly improve preformances for big files.
// return (chan *GoEvtxMap)
func (ef *File) UnorderedEvents() (cgem chan *GoEvtxMap) {
	cgem = make(chan *GoEvtxMap, 42)
	d := ef.scanDeduper("UnorderedEvents")
	go func() {
		defer close(cgem)
		chanQueue := make(chan (<-chan eventEnvelope), MaxJobs)
		go func() {
			defer close(chanQueue)
			for pc := range ef.UnorderedChunks() {
				// We have to create a copy here because otherwise cpc.EventsChan() fails
				// I guess that because EventsChan takes a pointer to an object and that
				// and thus the chan is taken on the pointer and since the object pointed
				// changes -> kaboom
				cpc, err := ef.FetchChunk(pc.Offset)
				ec, ok := ef.chunkEnvelopes(cpc, err)
				if ok {
					chanQueue <- ec
				}
			}
		}()
		for ec := range chanQueue {
			for env := range ec {
				if _, admit := d.Admit(env); admit {
					cgem <- env.gem
				}
			}
		}
	}()
	return
}

// MonitorEvents returns a chan pointers to all the GoEvtxMap found in the File
// under monitoring. This is the fast version
// @stop: a channel used to stop the monitoring if needed
// return (chan *GoEvtxMap)
func (ef *File) MonitorEvents(stop chan bool, sleep ...time.Duration) (cgem chan *GoEvtxMap) {
	sleepTime := DefaultMonitorSleep
	if len(sleep) > 0 {
		sleepTime = sleep[0]
	}
	jobs := MaxJobs
	cgem = make(chan *GoEvtxMap, 42)
	d := ef.scanDeduper("MonitorEvents")
	go func() {
		defer close(cgem)
		chanQueue := make(chan (<-chan eventEnvelope), jobs)
		go func() {
			defer close(chanQueue)
			// this chan ends only when value is put into stop
			for pc := range ef.monitorChunks(stop, sleepTime) {
				// We have to create a copy here because otherwise cpc.EventsChan() fails
				// I guess that because EventsChan takes a pointer to an object
				// and thus the chan is taken on the pointer and since the object pointed
				// changes -> kaboom
				cpc := pc
				chanQueue <- cpc.parsedEvents()
			}
		}()
		for ec := range chanQueue {
			for env := range ec {
				if _, admit := d.Admit(env); admit {
					cgem <- env.gem
				}
			}
		}
	}()
	return
}

// chunkEnvelopes preserves the historical fail-fast behavior for parser errors
// on ordinary opens. OpenDirty recovery mode additionally publishes event
// offsets already recovered before a chunk was found to be truncated.
func (ef *File) chunkEnvelopes(c Chunk, err error) (<-chan eventEnvelope, bool) {
	if err != nil && err != io.EOF && !ef.truncatedRecovery {
		panic(err)
	}
	if err != nil && len(c.EventOffsets) == 0 {
		return nil, false
	}
	return c.parsedEvents(), true
}

// Close file
func (ef *File) Close() error {
	if f, ok := ef.file.(io.Closer); ok {
		return f.Close()
	}

	return nil
}
