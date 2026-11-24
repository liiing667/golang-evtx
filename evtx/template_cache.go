package evtx

import (
	"bytes"
	"sync"
)

// TemplateID is the 16 bytes identifier embedded in every BinXML template
// definition. It is computed from the content of the template definition and
// therefore acts as its content identity: two template definitions with the
// same TemplateID are equivalent by construction.
type TemplateID [16]byte

// TemplateLocation identifies the physical location of a template definition
// inside an EVTX file. Both fields are needed because template data offsets
// are relative to the start of the chunk they belong to: the same offset in
// two different chunks may point to different template definitions.
type TemplateLocation struct {
	// ChunkOffset is the absolute offset of the chunk in the EVTX file.
	ChunkOffset int64
	// DataOffset is the offset of the template definition data relative to
	// the start of the chunk.
	DataOffset int32
}

// CachedTemplate stores a parsed template definition data together with the
// content identity (TemplateID) of the definition it has been parsed from.
type CachedTemplate struct {
	ID   TemplateID
	Data TemplateDefinitionData
}

// TemplateCache is a publicly accessible cache of parsed BinXML template
// definitions.
//
// A cache entry is bound to three identities:
//   - the chunk the template definition belongs to,
//   - the offset of the template definition within this chunk,
//   - the TemplateID (content hash) of the template definition.
//
// Binding entries to both the chunk and the offset prevents template
// definitions located at the same relative offset in different chunks from
// being confused with one another. Checking the TemplateID before reusing a
// cached definition guarantees that the cached content matches the template
// actually referenced. Definitions sharing the same TemplateID are known to
// be identical, which still allows identical templates to be shared across
// chunks without re-parsing them.
type TemplateCache struct {
	mu sync.RWMutex
	// locations indexes parsed template definitions by their physical
	// location (chunk offset + chunk relative data offset).
	locations map[TemplateLocation]CachedTemplate
	// byID indexes parsed template definitions by content identity. It is
	// what makes it possible to reuse identical templates across chunks.
	byID map[TemplateID]TemplateDefinitionData
}

// NewTemplateCache initializes and returns a new TemplateCache structure.
func NewTemplateCache() *TemplateCache {
	return &TemplateCache{
		locations: make(map[TemplateLocation]CachedTemplate),
		byID:      make(map[TemplateID]TemplateDefinitionData),
	}
}

// Lookup returns the template definition data cached at the given physical
// location together with the TemplateID it has been parsed from. The boolean
// returned is false if no template has ever been cached at this location.
func (tc *TemplateCache) Lookup(chunkOffset int64, dataOffset int32) (CachedTemplate, bool) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	ct, ok := tc.locations[TemplateLocation{chunkOffset, dataOffset}]
	return ct, ok
}

// Match reports whether the template definition cached at the given physical
// location has the provided content identity. It always returns false when
// nothing is cached at the location. This is the check that prevents a stale
// template from being reused when the same offset in another chunk (or an
// updated chunk) points to a different definition.
func (tc *TemplateCache) Match(chunkOffset int64, dataOffset int32, id TemplateID) bool {
	ct, ok := tc.Lookup(chunkOffset, dataOffset)
	return ok && bytes.Equal(ct.ID[:], id[:])
}

// LookupByID returns the template definition data associated to the given
// content identity. This allows identical templates to be shared across
// chunks: when a template has already been parsed somewhere in the file, any
// other location referencing a definition with the same TemplateID can reuse
// it safely.
func (tc *TemplateCache) LookupByID(id TemplateID) (TemplateDefinitionData, bool) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	tdd, ok := tc.byID[id]
	return tdd, ok
}

// Store caches a parsed template definition data at the given physical
// location and indexes it by its content identity so that it can be reused
// from any other chunk referencing the same TemplateID.
func (tc *TemplateCache) Store(chunkOffset int64, dataOffset int32, tdd TemplateDefinitionData) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	id := TemplateID(tdd.ID)
	tc.locations[TemplateLocation{chunkOffset, dataOffset}] = CachedTemplate{ID: id, Data: tdd}
	// Only keep the first parsed copy for a given content identity:
	// definitions with the same TemplateID are equivalent.
	if _, ok := tc.byID[id]; !ok {
		tc.byID[id] = tdd
	}
}

// Len returns the number of template definitions cached by physical location.
func (tc *TemplateCache) Len() int {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return len(tc.locations)
}

// defaultTemplateCache is the shared cache used by every Chunk when no
// explicit TemplateCache is configured. It is what enables identical
// templates to be shared across chunks while keeping location based entries
// isolated from one another.
var defaultTemplateCache = NewTemplateCache()

// defaultCacheMu protects the reference to the shared default template
// cache so that resetting it cannot race with concurrent chunk parsing.
var defaultCacheMu sync.RWMutex

// DefaultTemplateCache returns the shared TemplateCache used by chunks that
// do not configure their own one.
func DefaultTemplateCache() *TemplateCache {
	defaultCacheMu.RLock()
	defer defaultCacheMu.RUnlock()
	return defaultTemplateCache
}

// ResetDefaultTemplateCache empties the shared TemplateCache. It is mainly
// useful in tests and when several unrelated EVTX files are parsed in the
// same process.
func ResetDefaultTemplateCache() {
	defaultCacheMu.Lock()
	defer defaultCacheMu.Unlock()
	defaultTemplateCache = NewTemplateCache()
}
