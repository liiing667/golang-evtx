package evtx

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
)

func id(b byte) (t TemplateID) {
	for i := range t {
		t[i] = b
	}
	return
}

func TestTemplateCacheLocationAndContentBinding(t *testing.T) {
	tc := NewTemplateCache()
	idA := id(0xAA)
	idB := id(0xBB)

	tddA := TemplateDefinitionData{ID: idA, Size: 1}
	tddB := TemplateDefinitionData{ID: idB, Size: 2}

	// Two different chunks, same relative offset, different definitions.
	tc.Store(0x10000, 0x200, tddA)
	tc.Store(0x20000, 0x200, tddB)

	if got, ok := tc.Lookup(0x10000, 0x200); !ok || got.ID != idA {
		t.Fatalf("expected definition A at chunk 0x10000 offset 0x200, got %v %v", got, ok)
	}
	if got, ok := tc.Lookup(0x20000, 0x200); !ok || got.ID != idB {
		t.Fatalf("expected definition B at chunk 0x20000 offset 0x200, got %v %v", got, ok)
	}

	// Content identity matching at a given location.
	if !tc.Match(0x10000, 0x200, idA) {
		t.Fatal("Match should succeed for the correct TemplateID")
	}
	if tc.Match(0x10000, 0x200, idB) {
		t.Fatal("Match should fail when TemplateID differs: stale template would be reused")
	}
	if tc.Match(0x30000, 0x200, idA) {
		t.Fatal("Match should fail when nothing is cached at the location")
	}

	// Same content identity must be shareable across chunks.
	if got, ok := tc.LookupByID(idA); !ok || got.Size != 1 {
		t.Fatalf("expected to find definition A by content identity, got %v %v", got, ok)
	}
	if got, ok := tc.LookupByID(idB); !ok || got.Size != 2 {
		t.Fatalf("expected to find definition B by content identity, got %v %v", got, ok)
	}
}

func TestTemplateCacheCrossChunkSharing(t *testing.T) {
	tc := NewTemplateCache()
	idA := id(0xAA)
	tddA := TemplateDefinitionData{ID: idA, Size: 7}

	// The same template (same TemplateID) appears at different locations in
	// two chunks: it must be parsed once and reused through content identity.
	tc.Store(0x10000, 0x200, tddA)
	tc.Store(0x20000, 0x300, tddA)

	c1 := Chunk{Offset: 0x10000, Templates: tc}
	c2 := Chunk{Offset: 0x20000, Templates: tc}

	if got, ok := c1.lookupTemplate(0x200, idA); !ok || got.Size != 7 {
		t.Fatalf("chunk1 should reuse its cached template, got %v %v", got, ok)
	}
	if got, ok := c2.lookupTemplate(0x300, idA); !ok || got.Size != 7 {
		t.Fatalf("chunk2 should reuse the identical template by content identity, got %v %v", got, ok)
	}

	// Different content at the same relative offset must not be reused.
	idB := id(0xBB)
	c3 := Chunk{Offset: 0x30000, Templates: tc}
	if _, ok := c3.lookupTemplate(0x200, idB); ok {
		t.Fatal("chunk3 must not reuse chunk1 template when content identity differs")
	}
	// But it can still reuse A by content identity.
	if got, ok := c3.lookupTemplate(0x999, idA); !ok || got.Size != 7 {
		t.Fatalf("chunk3 should reuse template A by content identity, got %v %v", got, ok)
	}
}

// buildTemplateDefinition builds the bytes of a template definition data
// containing a single element whose name is elementName, followed by an EOF
// token. baseOffset is the chunk relative offset at which the definition is
// placed, it is needed to compute chunk relative name offsets.
func buildTemplateDefinition(guid TemplateID, elementName string, baseOffset int32) []byte {
	var def bytes.Buffer
	binary.Write(&def, Endianness, int32(0)) // Unknown3
	def.Write(guid[:])                       // ID (content identity)
	// Size is patched later: size of everything following the Size field
	// (FragHeader + elements + EOF).
	sizeOff := def.Len()
	binary.Write(&def, Endianness, int32(0)) // Size

	// FragmentHeader
	binary.Write(&def, Endianness, int8(FragmentHeaderToken))
	binary.Write(&def, Endianness, int8(1)) // MajVersion
	binary.Write(&def, Endianness, int8(1)) // MinVersion
	binary.Write(&def, Endianness, int8(0)) // Flags

	// ElementStart token (tag1)
	binary.Write(&def, Endianness, int8(TokenOpenStartElementTag1))
	// DepID is present because the element is part of a template
	// definition (it is parsed with the template instance flag set).
	binary.Write(&def, Endianness, int16(0))
	binary.Write(&def, Endianness, int32(0)) // Size of element
	// NameOffset is relative to the chunk start. The name structure is
	// written right after the 4 byte NameOffset field, so the name
	// position is the placeholder position plus the placeholder size.
	nameOffsetIndex := def.Len()
	binary.Write(&def, Endianness, int32(0)) // placeholder for NameOffset
	nameOffset := baseOffset + int32(nameOffsetIndex) + 4

	// Name structure (BinXMLName) at the current position
	utf16 := make([]uint16, len(elementName)+1)
	for i, r := range elementName {
		utf16[i] = uint16(r)
	}
	binary.Write(&def, Endianness, int32(0))                 // OffsetPrevString
	binary.Write(&def, Endianness, uint16(0))                // Hash
	binary.Write(&def, Endianness, uint16(len(elementName))) // Size
	for _, u := range utf16 {
		binary.Write(&def, Endianness, u)
	}
	binary.Write(&def, Endianness, uint8(TokenCloseEmptyElementTag))
	// EOF
	binary.Write(&def, Endianness, int8(TokenEOF))

	body := def.Bytes()
	binary.LittleEndian.PutUint32(body[sizeOff:sizeOff+4], uint32(def.Len()-sizeOff-4))
	// Patch the name offset once the buffer has finished growing, otherwise
	// Bytes() could return a stale backing array after reallocation.
	binary.LittleEndian.PutUint32(body[nameOffsetIndex:nameOffsetIndex+4], uint32(nameOffset))
	return body
}

// buildTemplateInstance builds the bytes of a template instance referencing
// a definition located at defOffset (relative to chunk start), with one
// string substitution value.
func buildTemplateInstance(defOffset int32, value string) []byte {
	var inst bytes.Buffer
	// TemplateInstance token
	binary.Write(&inst, Endianness, int8(TokenTemplateInstance))
	// TemplateDefinitionHeader
	binary.Write(&inst, Endianness, int8(0))   // Unknown1
	binary.Write(&inst, Endianness, int32(0))  // Unknown2
	binary.Write(&inst, Endianness, defOffset) // DataOffset

	// TemplateInstanceData
	binary.Write(&inst, Endianness, int32(1)) // NumValues
	rawValue := make([]byte, 2*len(value))
	for i, r := range value {
		binary.LittleEndian.PutUint16(rawValue[2*i:2*i+2], uint16(r))
	}
	// One ValueDescriptor: size, type (StringType=0x01), unknown byte
	binary.Write(&inst, Endianness, uint16(len(rawValue)))
	binary.Write(&inst, Endianness, ValueType(StringType))
	binary.Write(&inst, Endianness, int8(0))
	// Value bytes are read directly according to the descriptor
	inst.Write(rawValue)
	return inst.Bytes()
}

// buildChunk builds an in-memory chunk containing a template instance at the
// beginning and the referenced template definition at defOffset. When cache
// is not nil it is used as the chunk template cache, which makes it possible
// to exercise a cache shared across chunks.
func buildChunk(chunkOffset int64, guid TemplateID, elementName, value string, defOffset int32, cache *TemplateCache) Chunk {
	def := buildTemplateDefinition(guid, elementName, defOffset)
	inst := buildTemplateInstance(defOffset, value)

	data := make([]byte, ChunkSize)
	copy(data, inst)
	copy(data[int(defOffset):], def)

	c := NewChunk()
	if cache != nil {
		c.SetTemplateCache(cache)
	}
	c.Offset = chunkOffset
	c.Data = data
	return c
}

func parseFirstTemplateInstance(t *testing.T, c *Chunk) *TemplateInstance {
	t.Helper()
	reader := bytes.NewReader(c.Data)
	elt, err := Parse(reader, c, false)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	switch v := elt.(type) {
	case *Fragment:
		ti, ok := v.BinXMLElement.(*TemplateInstance)
		if !ok {
			t.Fatalf("expected *TemplateInstance in fragment, got %T", v.BinXMLElement)
		}
		return ti
	case *TemplateInstance:
		return v
	default:
		t.Fatalf("expected *TemplateInstance or *Fragment, got %T", elt)
	}
	return nil
}

// TestSameOffsetDifferentDefinitionAcrossChunks reproduces the issue where
// two chunks contain different template definitions at the same relative
// offset. The cached definition must be bound to both the location and the
// content identity so that the second chunk does not reuse the stale first
// definition.
func TestSameOffsetDifferentDefinitionAcrossChunks(t *testing.T) {
	ResetDefaultTemplateCache()
	defer ResetDefaultTemplateCache()

	const defOffset int32 = 0x400
	guidA := id(0x01)
	guidB := id(0x02)
	// Both chunks explicitly share the same public template cache, which
	// is exactly the situation in which an offset only keyed cache would
	// hand a stale definition to the second chunk.
	shared := NewTemplateCache()

	chunkA := buildChunk(0x10000, guidA, "ElementA", "valueA", defOffset, shared)
	chunkB := buildChunk(0x20000, guidB, "ElementB", "valueB", defOffset, shared)

	tiA := parseFirstTemplateInstance(t, &chunkA)
	if name := tiA.Definition.Data.Elements[0].(*ElementStart).Name.String(); name != "ElementA" {
		t.Fatalf("chunkA: expected ElementA, got %q", name)
	}

	tiB := parseFirstTemplateInstance(t, &chunkB)
	nameB := tiB.Definition.Data.Elements[0].(*ElementStart).Name.String()
	if nameB != "ElementB" {
		t.Fatalf("chunkB: stale template reused, expected ElementB got %q (unverifiable parsing)", nameB)
	}
	if TemplateID(tiB.Definition.Data.ID) != guidB {
		t.Fatalf("chunkB: expected TemplateID %v, got %v", guidB, tiB.Definition.Data.ID)
	}

	// Both definitions must remain cached at their own location.
	if !shared.Match(0x10000, defOffset, guidA) {
		t.Fatal("definition A should be cached at chunkA location")
	}
	if !shared.Match(0x20000, defOffset, guidB) {
		t.Fatal("definition B should be cached at chunkB location")
	}
}

// TestIdenticalTemplateSharedAcrossChunks ensures that normal cross chunk
// sharing is preserved: identical templates (same TemplateID) at different
// locations are reused through the content identity index.
func TestIdenticalTemplateSharedAcrossChunks(t *testing.T) {
	ResetDefaultTemplateCache()
	defer ResetDefaultTemplateCache()

	guidA := id(0x01)
	chunkA := buildChunk(0x10000, guidA, "SharedElement", "valueA", 0x400, nil)
	chunkB := buildChunk(0x20000, guidA, "SharedElement", "valueB", 0x800, nil)

	tiA := parseFirstTemplateInstance(t, &chunkA)
	tiB := parseFirstTemplateInstance(t, &chunkB)

	if name := tiA.Definition.Data.Elements[0].(*ElementStart).Name.String(); name != "SharedElement" {
		t.Fatalf("chunkA: expected SharedElement, got %q", name)
	}
	if name := tiB.Definition.Data.Elements[0].(*ElementStart).Name.String(); name != "SharedElement" {
		t.Fatalf("chunkB: expected SharedElement, got %q", name)
	}
	if TemplateID(tiB.Definition.Data.ID) != guidA {
		t.Fatalf("chunkB: expected shared TemplateID %v, got %v", guidA, tiB.Definition.Data.ID)
	}
	// The per instance data must still come from each chunk.
	if got := tiB.Data.Values[0].(*ValueString).String(); got != "valueB" {
		t.Fatalf("chunkB: expected instance value valueB, got %q", got)
	}

	// Both locations must be populated while sharing the same content
	// identity entry.
	cache := DefaultTemplateCache()
	if cache.Len() != 2 {
		t.Fatalf("expected 2 location entries, got %d", cache.Len())
	}
	if _, ok := cache.LookupByID(guidA); !ok {
		t.Fatal("shared template should be reachable by content identity")
	}
}

// TestSameOffsetIdenticalTemplateAcrossChunks covers the exact layout of the
// bug report but with identical content: two chunks reference a template
// definition located at the same relative offset and carrying the same
// TemplateID. The definition must be shared instead of being confused with a
// stale one.
func TestSameOffsetIdenticalTemplateAcrossChunks(t *testing.T) {
	ResetDefaultTemplateCache()
	defer ResetDefaultTemplateCache()

	const defOffset int32 = 0x400
	guidA := id(0x07)
	shared := NewTemplateCache()
	chunkA := buildChunk(0x10000, guidA, "SharedElement", "valueA", defOffset, shared)
	chunkB := buildChunk(0x20000, guidA, "SharedElement", "valueB", defOffset, shared)

	tiA := parseFirstTemplateInstance(t, &chunkA)
	tiB := parseFirstTemplateInstance(t, &chunkB)

	for name, ti := range map[string]*TemplateInstance{"A": tiA, "B": tiB} {
		if got := ti.Definition.Data.Elements[0].(*ElementStart).Name.String(); got != "SharedElement" {
			t.Fatalf("chunk%s: expected SharedElement, got %q", name, got)
		}
		if TemplateID(ti.Definition.Data.ID) != guidA {
			t.Fatalf("chunk%s: TemplateID mismatch", name)
		}
	}
	if !shared.Match(0x10000, defOffset, guidA) || !shared.Match(0x20000, defOffset, guidA) {
		t.Fatal("both chunk locations should be bound to the same content identity")
	}
	// A single content identity entry backs both locations.
	if shared.Len() != 2 {
		t.Fatalf("expected 2 location entries, got %d", shared.Len())
	}
}

// TestTemplateCacheConcurrentAccess exercises the cache from several
// goroutines at once. It is meant to be run under the race detector.
func TestTemplateCacheConcurrentAccess(t *testing.T) {
	tc := NewTemplateCache()
	ids := []TemplateID{id(0x10), id(0x20), id(0x30), id(0x40)}
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				guid := ids[i%len(ids)]
				chunkOffset := int64(0x10000 * (1 + g))
				tdd := TemplateDefinitionData{ID: guid, Size: int32(i)}
				tc.Store(chunkOffset, int32(0x100+i), tdd)
				if _, ok := tc.Lookup(chunkOffset, int32(0x100+i)); !ok {
					t.Errorf("stored entry not found")
					return
				}
				tc.Match(chunkOffset, int32(0x100+i), guid)
				if _, ok := tc.LookupByID(guid); !ok {
					t.Errorf("content identity entry not found")
					return
				}
				_ = tc.Len()
			}
		}(g)
	}
	wg.Wait()
}
