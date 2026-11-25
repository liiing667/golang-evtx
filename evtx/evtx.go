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
	return cs[i].Header.NumFirstRecLog < cs[j].Header.NumFirstRecLog
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
	f.LastChunkNum = uint64(f.ChunkCount - 1)
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

	dedupMu sync.RWMutex
	deduper *RecordDeduper
}

// New EvtxFile structure initialized from an open buffer
// @r : buffer containing evtx data to parse
// return File : File structure initialized
func New(r io.ReadSeeker) (ef File, err error) {
	ef.file = r
	if f, ok := r.(*os.File); ok {
		ef.path = f.Name()
	}
	err = ef.readHeader()
	return
}

// New EvtxFile structure initialized from file
// @filepath : filepath of the evtx file to parse
// return File : File structure initialized
func Open(filepath string) (ef File, err error) {
	file, err := os.Open(filepath)
	if err != nil {
		return
	}

	ef, err = New(file)
	if err != nil {
		return
	}
	ef.path = filepath

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
	return
}

// Reset rewinds the underlying reader and reloads the committed file header.
// It also clears stream-local deduplication evidence. Rejected observations are
// never written to the EVTX, so a reset/reopen deterministically reconstructs
// the same evidence by scanning the immutable source again.
func (ef *File) Reset() error {
	ef.Lock()
	err := ef.readHeaderLocked()
	ef.Unlock()
	ef.dedupMu.Lock()
	ef.deduper = nil
	ef.dedupMu.Unlock()
	return err
}

// Reopen opens a path-backed File again and resets all in-memory scan state.
// Reader-backed Files are rewound instead.
func (ef *File) Reopen() error {
	ef.Lock()
	if ef.path != "" {
		f, err := os.Open(ef.path)
		if err != nil {
			ef.Unlock()
			return err
		}
		old := ef.file
		ef.file = f
		if closer, ok := old.(io.Closer); ok && old != nil {
			_ = closer.Close()
		}
	}
	err := ef.readHeaderLocked()
	ef.Unlock()
	ef.dedupMu.Lock()
	ef.deduper = nil
	ef.dedupMu.Unlock()
	return err
}

// SetMonitorExisting sets monitorExisting flag of EvtxFile struct in order to
// return already existing events when using MonitorEvents
func (ef *File) SetMonitorExisting(value bool) {
	ef.monitorExisting = value
}

// ParseFileHeader parses a the file header of the file structure and modifies
// the Header of the current structure
func (ef *File) ParseFileHeader() {
	ef.Lock()
	defer ef.Unlock()
	if err := ef.readHeaderLocked(); err != nil {
		panic(err)
	}
}

func (ef *File) readHeader() error {
	ef.Lock()
	defer ef.Unlock()
	return ef.readHeaderLocked()
}

func (ef *File) readHeaderLocked() error {
	if ef.file == nil {
		return io.EOF
	}
	if _, err := ef.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	ef.Header = FileHeader{}
	return encoding.Unmarshal(ef.file, &ef.Header, Endianness)
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
	GoToSeeker(ef.file, offset)
	c.Offset = offset
	c.Data = make([]byte, ChunkHeaderSize)
	if _, err := ef.file.Read(c.Data); err != nil {
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
	GoToSeeker(ef.file, offset)
	c.Offset = offset
	c.Data = make([]byte, ChunkSize)
	if _, err := ef.file.Read(c.Data); err != nil {
		return c, err
	}
	reader := bytes.NewReader(c.Data)
	c.ParseChunkHeader(reader)
	// Go to after Header
	GoToSeeker(reader, int64(c.Header.SizeHeader))
	c.ParseStringTable(reader)
	if err := c.ParseTemplateTable(reader); err != nil {
		return c, err
	}
	if err := c.ParseEventOffsets(reader); err != nil {
		return c, err
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
				case err != nil && err != io.EOF:
					panic(err)
				case err == nil:
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
	d := ef.newDeduper("Events")
	go func() {
		defer close(cgem)
		for c := range ef.Chunks() {
			cpc, err := ef.FetchChunk(c.Offset)
			switch {
			case err != nil && err != io.EOF:
				panic(err)
			case err == nil:
				for env := range cpc.parsedEvents() {
					if _, ok := d.Admit(env); ok {
						cgem <- env.gem
					}
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
	d := ef.newDeduper("FastEvents")
	go func() {
		defer close(cgem)
		chanQueue := make(chan (<-chan eventEnvelope), MaxJobs)
		go func() {
			defer close(chanQueue)
			for pc := range ef.Chunks() {
				cpc, err := ef.FetchChunk(pc.Offset)
				switch {
				case err != nil && err != io.EOF:
					panic(err)
				case err == nil:
					chanQueue <- cpc.parsedEvents()
				}
			}
		}()
		for ec := range chanQueue {
			for env := range ec {
				log.Debug(env.gem)
				if _, ok := d.Admit(env); ok {
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
	d := ef.newDeduper("UnorderedEvents")
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
				switch {
				case err != nil && err != io.EOF:
					panic(err)
				case err == nil:
					chanQueue <- cpc.parsedEvents()
				}
			}
		}()
		for ec := range chanQueue {
			for env := range ec {
				if _, ok := d.Admit(env); ok {
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
	d := ef.newDeduper("MonitorEvents")
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
				if _, ok := d.Admit(env); ok {
					cgem <- env.gem
				}
			}
		}
	}()
	return
}

// Close file
func (ef *File) Close() error {
	if f, ok := ef.file.(io.Closer); ok {
		return f.Close()
	}

	return nil
}
