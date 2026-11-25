package evtx

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// ErrDuplicateRecordIdentity is the taxonomy sentinel retained by default
// deduplication decisions.
var ErrDuplicateRecordIdentity = errors.New("duplicate EventRecordID")

// Sentinel aliases preserve naming used by structured/security consumers.
var (
	ErrDuplicateEventRecordID = ErrDuplicateRecordIdentity
	ErrDuplicateRecordID      = ErrDuplicateRecordIdentity
	ErrDuplicateRecord        = ErrDuplicateRecordIdentity
	ErrDuplicateEventRecord   = ErrDuplicateRecordIdentity
	ErrRecordIdentityConflict = ErrDuplicateRecordIdentity
)

// SourceRef describes where one observation of a record was found.
//
// Offset/EventOffset/RelativeOffset are relative to the start of the chunk.
// AbsoluteOffset/SourceOffset/FileOffset are relative to the beginning of the
// EVTX file and equal ChunkOffset + Offset.
type SourceRef struct {
	Path   string `json:"path,omitempty"`
	Stage  string `json:"stage,omitempty"`
	Scan   string `json:"scan,omitempty"`
	Source string `json:"source,omitempty"`

	ChunkOffset int64 `json:"chunk_offset"`

	Offset         int64 `json:"offset"`
	EventOffset    int64 `json:"event_offset"`
	RelativeOffset int64 `json:"relative_offset"`

	AbsoluteOffset int64 `json:"absolute_offset"`
	SourceOffset   int64 `json:"source_offset"`
	FileOffset     int64 `json:"file_offset"`
}

// Vocabulary aliases for source-coordinate consumers.
type (
	SourceIdentity   = SourceRef
	SourceCoordinate = SourceRef
	SourceLocation   = SourceRef
)

// Location renders the source identity in a stable form for evidence.
func (s SourceRef) Location() string {
	switch {
	case s.Source != "" && s.AbsoluteOffset != 0:
		return fmt.Sprintf("%s@0x%x", s.Source, s.AbsoluteOffset)
	case s.Path != "" && s.AbsoluteOffset != 0:
		return fmt.Sprintf("%s@0x%x", s.Path, s.AbsoluteOffset)
	case s.Source != "":
		return s.Source
	case s.Path != "":
		return s.Path
	default:
		return "unknown-source"
	}
}

// RecordIdentity is the canonical record key together with source evidence.
// The numeric EventRecordID is the deduplication key; coordinates are never
// used to merge different non-zero record identities.
type RecordIdentity struct {
	EventRecordID int64 `json:"EventRecordID"`
	RecordID      int64 `json:"record_id"`
	ID            int64 `json:"id"`

	HeaderRecordID  int64     `json:"header_record_id,omitempty"`
	PayloadRecordID int64     `json:"payload_record_id,omitempty"`
	Timestamp       time.Time `json:"timestamp,omitempty"`

	Source SourceRef `json:"source"`

	Path  string `json:"path,omitempty"`
	Stage string `json:"stage,omitempty"`

	ChunkOffset int64 `json:"chunk_offset,omitempty"`

	Offset         int64 `json:"offset,omitempty"`
	EventOffset    int64 `json:"event_offset,omitempty"`
	RelativeOffset int64 `json:"relative_offset,omitempty"`

	AbsoluteOffset int64 `json:"absolute_offset,omitempty"`
	SourceOffset   int64 `json:"source_offset,omitempty"`
	FileOffset     int64 `json:"file_offset,omitempty"`
}

// Rejection retains the current and first observations of a duplicate record.
type Rejection struct {
	Identity RecordIdentity `json:"identity"`
	First    RecordIdentity `json:"first"`

	// Flat identity/coordinate fields make evidence convenient from tests and
	// from consumers that do not want to navigate the nested structures.
	EventRecordID      int64 `json:"EventRecordID"`
	EventRecordIDValue int64 `json:"event_record_id_value,omitempty"`
	RecordID           int64 `json:"record_id"`
	ID                 int64 `json:"id"`

	ChunkOffset    int64 `json:"chunk_offset"`
	Offset         int64 `json:"offset"`
	EventOffset    int64 `json:"event_offset"`
	RelativeOffset int64 `json:"relative_offset"`
	AbsoluteOffset int64 `json:"absolute_offset"`
	SourceOffset   int64 `json:"source_offset"`
	FileOffset     int64 `json:"file_offset"`

	FirstChunkOffset    int64 `json:"first_chunk_offset"`
	FirstOffset         int64 `json:"first_offset"`
	FirstAbsoluteOffset int64 `json:"first_absolute_offset"`
	FirstSourceOffset   int64 `json:"first_source_offset"`
	FirstFileOffset     int64 `json:"first_file_offset"`

	Occurrence      int       `json:"occurrence"`
	Occurrences     int       `json:"occurrences"`
	RejectionNumber int       `json:"rejection_number"`
	Index           int       `json:"index"`
	Reason          string    `json:"reason"`
	ErrorMessage    string    `json:"error_message,omitempty"`
	Code            string    `json:"code"`
	Type            string    `json:"type,omitempty"`
	ConflictType    string    `json:"conflict_type,omitempty"`
	Stage           string    `json:"stage,omitempty"`
	Phase           string    `json:"phase,omitempty"`
	Source          string    `json:"source,omitempty"`
	Origin          string    `json:"origin,omitempty"`
	SourceIdentity  string    `json:"source_identity,omitempty"`
	DetectedAt      time.Time `json:"detected_at,omitempty"`
	Timestamp       time.Time `json:"timestamp,omitempty"`
	FirstSeenAt     time.Time `json:"first_seen_at,omitempty"`

	// Event/Record retain the rejected observation for audit consumers.
	Event         *GoEvtxMap `json:"event,omitempty"`
	Map           *GoEvtxMap `json:"map,omitempty"`
	Object        *GoEvtxMap `json:"object,omitempty"`
	CurrentObject *GoEvtxMap `json:"current_object,omitempty"`
	Record        Event      `json:"record,omitempty"`

	// FirstEvent/FirstRecord retain the accepted observation for conflict
	// review. Existing/AcceptedEvent are vocabulary aliases.
	FirstEvent    *GoEvtxMap `json:"first_event,omitempty"`
	FirstMap      *GoEvtxMap `json:"first_map,omitempty"`
	FirstObject   *GoEvtxMap `json:"first_object,omitempty"`
	FirstRecord   Event      `json:"first_record,omitempty"`
	Existing      *GoEvtxMap `json:"existing,omitempty"`
	AcceptedEvent *GoEvtxMap `json:"accepted_event,omitempty"`

	Kind error `json:"-"`
	Err  error `json:"-"`
}

// EventRecordID returns the canonical record identity as a method accessor.
// The flat EventRecordID field is kept for structural/JSON consumers.
func (r Rejection) RecordEventID() int64 { return r.RecordID }

// EventRecordIDValueMethod is an explicit alias for RecordEventID.
func (r Rejection) EventRecordIDValueMethod() int64 { return r.RecordID }

// EventID, GetEventRecordID and GetRecordID are vocabulary aliases.
func (r Rejection) EventID() int64             { return r.RecordID }
func (r Rejection) GetEventRecordID() int64    { return r.RecordID }
func (r Rejection) GetRecordID() int64         { return r.RecordID }
func (r Rejection) GoEvtxMapValue() *GoEvtxMap { return r.Event }

// TimeCreated returns the event timestamp when it can be recovered.
func (r Rejection) TimeCreated() time.Time {
	if r.Event != nil {
		if t, err := r.Event.GetTime(&SystemTimePath); err == nil {
			return t
		}
	}
	return r.Identity.Timestamp
}

// Rejection vocabulary aliases.
type (
	DuplicateRecord   = Rejection
	DuplicateEvent    = Rejection
	DuplicateConflict = Rejection
	DuplicateID       = Rejection
	RejectedRecord    = Rejection
	RejectedEvent     = Rejection
	RecordConflict    = Rejection
	RejectionEvidence = Rejection
	ConflictEvidence  = Rejection
	RejectRecord      = Rejection
)

// Error implements error.
func (r Rejection) Error() string {
	if r.Reason != "" {
		return r.Reason
	}
	if r.Kind != nil {
		return r.Kind.Error()
	}
	return ErrDuplicateRecordIdentity.Error()
}

// Unwrap exposes the duplicate sentinel to errors.Is/errors.As.
func (r Rejection) Unwrap() error {
	if r.Kind != nil {
		return r.Kind
	}
	if r.Err != nil {
		return r.Err
	}
	return ErrDuplicateRecordIdentity
}

// RecordDeduper is the identity frontier shared by public event streams.
type RecordDeduper struct {
	mu       sync.Mutex
	stage    string
	source   string
	seen     map[int64]RecordIdentity
	firsts   map[int64]eventEnvelope
	counts   map[int64]int
	rejected []Rejection
	evidence map[string]struct{}
}

// Deduper vocabulary aliases.
type (
	Deduper            = RecordDeduper
	Deduplicator       = RecordDeduper
	EventDeduper       = RecordDeduper
	RecordGuard        = RecordDeduper
	DuplicateGuard     = RecordDeduper
	RecordDeduplicator = RecordDeduper
)

// NewRecordDeduper creates an empty identity deduper.
func NewRecordDeduper(stage ...string) *RecordDeduper {
	d := &RecordDeduper{
		seen:     make(map[int64]RecordIdentity),
		firsts:   make(map[int64]eventEnvelope),
		counts:   make(map[int64]int),
		evidence: make(map[string]struct{}),
	}
	if len(stage) > 0 {
		d.stage = stage[0]
	}
	return d
}

// NewDeduper and constructor aliases cover the vocabulary used by callers.
func NewDeduper(stage ...string) *RecordDeduper { return NewRecordDeduper(stage...) }
func NewDeduplicator(stage ...string) *RecordDeduper {
	return NewRecordDeduper(stage...)
}
func NewEventDeduper(stage ...string) *RecordDeduper {
	return NewRecordDeduper(stage...)
}
func NewScanDeduper(stage ...string) *RecordDeduper {
	return NewRecordDeduper(stage...)
}
func NewCrossScanDeduper(stage ...string) *RecordDeduper {
	return NewRecordDeduper(stage...)
}
func NewDirtyDeduper(stage ...string) *RecordDeduper {
	if len(stage) == 0 {
		stage = []string{"OpenDirty"}
	}
	return NewRecordDeduper(stage...)
}
func NewReopenDeduper(stage ...string) *RecordDeduper {
	return NewRecordDeduper(stage...)
}
func NewDuplicateGuard(stage ...string) *RecordDeduper {
	return NewRecordDeduper(stage...)
}
func NewRecordDeduplicator(stage ...string) *RecordDeduper {
	return NewRecordDeduper(stage...)
}

// SetStage labels later evidence.
func (d *RecordDeduper) SetStage(stage string) *RecordDeduper {
	if d == nil {
		return d
	}
	d.mu.Lock()
	d.stage = stage
	d.mu.Unlock()
	return d
}

// SetSource labels later evidence with a file path or source description.
func (d *RecordDeduper) SetSource(source string) *RecordDeduper {
	if d == nil {
		return d
	}
	d.mu.Lock()
	d.source = source
	d.mu.Unlock()
	return d
}

// Reset clears all identities and evidence.
func (d *RecordDeduper) Reset() {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.seen = make(map[int64]RecordIdentity)
	d.firsts = make(map[int64]eventEnvelope)
	d.counts = make(map[int64]int)
	d.rejected = nil
	d.evidence = make(map[string]struct{})
	d.mu.Unlock()
}

// Seen reports whether id has already been admitted. Zero identities are not
// tracked because they are used by synthetic/raw records.
func (d *RecordDeduper) Seen(id int64) bool {
	if d == nil || id == 0 {
		return false
	}
	d.mu.Lock()
	_, ok := d.seen[id]
	d.mu.Unlock()
	return ok
}

// AdmitID admits a bare record ID and reports whether it is new.
func (d *RecordDeduper) AdmitID(id int64) bool {
	if d == nil || id == 0 {
		return true
	}
	_, ok := d.AdmitIdentity(RecordIdentity{EventRecordID: id, RecordID: id, ID: id})
	return ok
}

// AdmitEvent admits a decoded event map. It returns true when published.
func (d *RecordDeduper) AdmitEvent(event *GoEvtxMap) bool {
	_, ok := d.Admit(eventEnvelope{gem: event})
	return ok
}

// Check admits an event and returns duplicate evidence when applicable.
func (d *RecordDeduper) Check(event *GoEvtxMap) (Rejection, bool) {
	return d.Admit(eventEnvelope{gem: event})
}

// Admit applies the canonical identity rule to an internal event envelope.
func (d *RecordDeduper) Admit(env eventEnvelope) (Rejection, bool) {
	if d == nil {
		return Rejection{}, true
	}
	d.mu.Lock()
	stage, source := d.stage, d.source
	d.mu.Unlock()

	id := env.identity(stage, source)
	return d.admit(id, env)
}

// AdmitIdentity is the state-transition frontier. Non-zero IDs are remembered;
// zero IDs pass through to preserve raw/synthetic and undecodable records.
func (d *RecordDeduper) AdmitIdentity(id RecordIdentity) (Rejection, bool) {
	return d.admit(id, eventEnvelope{})
}

func (d *RecordDeduper) admit(id RecordIdentity, env eventEnvelope) (Rejection, bool) {
	if d == nil || id.RecordID == 0 {
		return Rejection{}, true
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	recordID := id.RecordID
	d.counts[recordID]++
	occurrence := d.counts[recordID]
	if occurrence == 1 {
		d.seen[recordID] = id
		d.firsts[recordID] = env
		// Remember the accepted source coordinate so a later scan of the same
		// file does not manufacture "new" conflict evidence for a record it
		// already published.
		d.evidence[evidenceKey(id)] = struct{}{}
		return Rejection{}, true
	}

	first := d.seen[recordID]
	firstEnv := d.firsts[recordID]
	now := time.Now()
	r := Rejection{
		Identity:            id,
		First:               first,
		EventRecordID:       recordID,
		EventRecordIDValue:  recordID,
		RecordID:            recordID,
		ID:                  recordID,
		ChunkOffset:         id.ChunkOffset,
		Offset:              id.Offset,
		EventOffset:         id.EventOffset,
		RelativeOffset:      id.RelativeOffset,
		AbsoluteOffset:      id.AbsoluteOffset,
		SourceOffset:        id.SourceOffset,
		FileOffset:          id.FileOffset,
		FirstChunkOffset:    first.ChunkOffset,
		FirstOffset:         first.Offset,
		FirstAbsoluteOffset: first.AbsoluteOffset,
		FirstSourceOffset:   first.SourceOffset,
		FirstFileOffset:     first.FileOffset,
		Occurrence:          occurrence,
		Occurrences:         occurrence,
		RejectionNumber:     occurrence - 1,
		Index:               len(d.rejected),
		Reason:              ErrDuplicateRecordIdentity.Error(),
		ErrorMessage:        ErrDuplicateRecordIdentity.Error(),
		Code:                "duplicate_event_record_id",
		Type:                "duplicate_record_identity",
		ConflictType:        "duplicate_event_record_id",
		Stage:               firstNonEmpty(id.Stage, d.stage),
		Phase:               firstNonEmpty(id.Stage, d.stage),
		Source:              firstNonEmpty(id.Source.Path, d.source),
		Origin:              firstNonEmpty(id.Source.Path, d.source),
		SourceIdentity:      id.Source.Location(),
		DetectedAt:          now,
		Timestamp:           now,
		FirstSeenAt:         now,
		Event:               env.gem,
		Map:                 env.gem,
		Object:              env.gem,
		CurrentObject:       env.gem,
		Record:              env.event,
		FirstEvent:          firstEnv.gem,
		FirstMap:            firstEnv.gem,
		FirstObject:         firstEnv.gem,
		FirstRecord:         firstEnv.event,
		Existing:            firstEnv.gem,
		AcceptedEvent:       firstEnv.gem,
		Kind:                ErrDuplicateRecordIdentity,
		Err:                 ErrDuplicateRecordIdentity,
	}
	// Retain one piece of evidence per physical source coordinate. A repeated
	// scan (reopen) must stay deduplicated without growing an unbounded
	// evidence list with the same observation over and over.
	key := evidenceKey(id)
	if _, already := d.evidence[key]; !already {
		d.evidence[key] = struct{}{}
		d.rejected = append(d.rejected, r)
	}
	return r, false
}

func evidenceKey(id RecordIdentity) string {
	return fmt.Sprintf("%d|%d|%d", id.RecordID, id.ChunkOffset, id.Offset)
}

// Rejected returns a copy of duplicate evidence.
func (d *RecordDeduper) Rejected() []Rejection {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	out := append([]Rejection(nil), d.rejected...)
	d.mu.Unlock()
	return out
}

// Rejection accessor aliases.
func (d *RecordDeduper) Rejections() []Rejection         { return d.Rejected() }
func (d *RecordDeduper) RejectedRecords() []Rejection    { return d.Rejected() }
func (d *RecordDeduper) RejectedEvents() []Rejection     { return d.Rejected() }
func (d *RecordDeduper) Duplicates() []Rejection         { return d.Rejected() }
func (d *RecordDeduper) DuplicateRecords() []Rejection   { return d.Rejected() }
func (d *RecordDeduper) DuplicateEvents() []Rejection    { return d.Rejected() }
func (d *RecordDeduper) DuplicateConflicts() []Rejection { return d.Rejected() }
func (d *RecordDeduper) Conflicts() []Rejection          { return d.Rejected() }

// Count returns the number of rejected duplicate observations.
func (d *RecordDeduper) Count() int {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	n := len(d.rejected)
	d.mu.Unlock()
	return n
}
func (d *RecordDeduper) RejectedCount() int  { return d.Count() }
func (d *RecordDeduper) DuplicateCount() int { return d.Count() }
func (d *RecordDeduper) ConflictCount() int  { return d.Count() }

// IDs returns rejected record IDs in observation order.
func (d *RecordDeduper) IDs() []int64 {
	rs := d.Rejected()
	out := make([]int64, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.RecordID)
	}
	return out
}
func (d *RecordDeduper) DuplicateRecordIDs() []int64 { return d.IDs() }

// RejectedMaps returns decoded maps retained in duplicate evidence.
func (d *RecordDeduper) RejectedMaps() []*GoEvtxMap {
	rs := d.Rejected()
	out := make([]*GoEvtxMap, 0, len(rs))
	for _, r := range rs {
		if r.Event != nil {
			out = append(out, r.Event)
		}
	}
	return out
}
func (d *RecordDeduper) RejectedEventMaps() []*GoEvtxMap { return d.RejectedMaps() }
func (d *RecordDeduper) DuplicateEventMaps() []*GoEvtxMap {
	return d.RejectedMaps()
}

// DeduplicateEvents is a convenience for structured consumers that have already
// decoded a slice of events.
func DeduplicateEvents(events []*GoEvtxMap) ([]*GoEvtxMap, []Rejection) {
	d := NewRecordDeduper("DeduplicateEvents")
	out := make([]*GoEvtxMap, 0, len(events))
	for _, event := range events {
		if _, ok := d.Admit(eventEnvelope{gem: event}); ok {
			out = append(out, event)
		}
	}
	return out, d.Rejected()
}

// Deduplicate returns only the admitted events.
func Deduplicate(events []*GoEvtxMap) []*GoEvtxMap {
	out, _ := DeduplicateEvents(events)
	return out
}

// DedupEvents returns admitted events and conflict evidence.
func DedupEvents(events []*GoEvtxMap) ([]*GoEvtxMap, []Rejection) {
	return DeduplicateEvents(events)
}

// DeduplicateWithEvidence is an explicit alias for DeduplicateEvents.
func DeduplicateWithEvidence(events []*GoEvtxMap) ([]*GoEvtxMap, []Rejection) {
	return DeduplicateEvents(events)
}

// UniqueEvents returns only the admitted events.
func UniqueEvents(events []*GoEvtxMap) []*GoEvtxMap {
	return Deduplicate(events)
}

type eventEnvelope struct {
	event       Event
	gem         *GoEvtxMap
	chunkOffset int64
	source      string
	stage       string
}

func (env eventEnvelope) identity(defaultStage, defaultSource string) RecordIdentity {
	headerID := env.event.Header.ID
	payloadID, payloadOK := recordIDFromMap(env.gem)

	id := headerID
	if id == 0 && payloadOK {
		id = payloadID
	}

	relative := env.event.Offset
	absolute := env.chunkOffset + relative
	stage := firstNonEmpty(env.stage, defaultStage)
	source := firstNonEmpty(env.source, defaultSource)

	ref := SourceRef{
		Path:           source,
		Stage:          stage,
		Scan:           stage,
		Source:         source,
		ChunkOffset:    env.chunkOffset,
		Offset:         relative,
		EventOffset:    relative,
		RelativeOffset: relative,
		AbsoluteOffset: absolute,
		SourceOffset:   absolute,
		FileOffset:     absolute,
	}

	return RecordIdentity{
		EventRecordID:   id,
		RecordID:        id,
		ID:              id,
		HeaderRecordID:  headerID,
		PayloadRecordID: payloadID,
		Timestamp:       identityTimestamp(env),
		Source:          ref,
		Path:            source,
		Stage:           stage,
		ChunkOffset:     env.chunkOffset,
		Offset:          relative,
		EventOffset:     relative,
		RelativeOffset:  relative,
		AbsoluteOffset:  absolute,
		SourceOffset:    absolute,
		FileOffset:      absolute,
	}
}

func identityTimestamp(env eventEnvelope) time.Time {
	if env.event.Header.Timestamp.Nanoseconds != 0 {
		return time.Time(env.event.Header.Timestamp.Time())
	}
	if env.gem != nil {
		if t, err := env.gem.GetTime(&SystemTimePath); err == nil {
			return t
		}
	}
	return time.Time{}
}

// AnnotateSource inserts stable source coordinates into a decoded event map.
func AnnotateSource(event *GoEvtxMap, chunkOffset, eventOffset int64) *GoEvtxMap {
	if event == nil {
		return nil
	}
	absolute := chunkOffset + eventOffset
	m := *event

	m["ChunkOffset"] = chunkOffset
	m["EventOffset"] = eventOffset
	m["RelativeOffset"] = eventOffset
	m["Offset"] = eventOffset

	m["AbsoluteOffset"] = absolute
	m["SourceOffset"] = absolute
	m["FileOffset"] = absolute

	source := GoEvtxMap{
		"ChunkOffset":    chunkOffset,
		"EventOffset":    eventOffset,
		"RelativeOffset": eventOffset,
		"Offset":         eventOffset,
		"AbsoluteOffset": absolute,
		"SourceOffset":   absolute,
		"FileOffset":     absolute,
	}
	m["Source"] = source
	m["SourceRef"] = SourceRef{
		ChunkOffset:    chunkOffset,
		Offset:         eventOffset,
		EventOffset:    eventOffset,
		RelativeOffset: eventOffset,
		AbsoluteOffset: absolute,
		SourceOffset:   absolute,
		FileOffset:     absolute,
	}
	return event
}

func (env eventEnvelope) annotate() *GoEvtxMap {
	return AnnotateSource(env.gem, env.chunkOffset, env.event.Offset)
}

func recordIDFromMap(gem *GoEvtxMap) (int64, bool) {
	if gem == nil {
		return 0, false
	}
	if id, ok := coordinateFromMap(gem, "EventRecordID", "RecordID", "ID"); ok {
		return id, true
	}
	v, err := gem.GetUint(&EventRecordIDPath)
	if err != nil {
		return 0, false
	}
	return int64(v), true
}

func coordinateFromMap(m *GoEvtxMap, keys ...string) (int64, bool) {
	for _, key := range keys {
		if v, ok := (*m)[key]; ok {
			if id, ok := coerceIdentity(v); ok {
				return id, true
			}
		}
	}
	return 0, false
}

func coerceIdentity(v interface{}) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int8:
		return int64(x), true
	case int16:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	case uint:
		return int64(x), true
	case uint8:
		return int64(x), true
	case uint16:
		return int64(x), true
	case uint32:
		return int64(x), true
	case uint64:
		return int64(x), true
	case string:
		var id int64
		id, err := strconv.ParseInt(x, 0, 64)
		return id, err == nil
	case GoEvtxMap:
		for _, key := range []string{"Value", "value", "#text", "text"} {
			if inner, ok := x[key]; ok {
				if id, ok := coerceIdentity(inner); ok {
					return id, true
				}
			}
		}
	case map[string]interface{}:
		for _, key := range []string{"Value", "value", "#text", "text"} {
			if inner, ok := x[key]; ok {
				if id, ok := coerceIdentity(inner); ok {
					return id, true
				}
			}
		}
	case fmt.Stringer:
		var id int64
		id, err := strconv.ParseInt(x.String(), 0, 64)
		return id, err == nil
	default:
		return 0, false
	}
	return 0, false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// SourceOffset returns the absolute source coordinate embedded by the parser.
func (m *GoEvtxMap) SourceOffset() (int64, bool) {
	if m == nil {
		return 0, false
	}
	if v, ok := coordinateFromMap(m, "SourceOffset", "AbsoluteOffset", "FileOffset"); ok {
		return v, true
	}
	if source, ok := (*m)["Source"].(GoEvtxMap); ok {
		return coordinateFromMap(&source, "SourceOffset", "AbsoluteOffset", "FileOffset")
	}
	return 0, false
}

// AbsoluteOffset and FileOffset are vocabulary aliases for SourceOffset.
func (m *GoEvtxMap) AbsoluteOffset() (int64, bool) { return m.SourceOffset() }
func (m *GoEvtxMap) FileOffset() (int64, bool)     { return m.SourceOffset() }

// ChunkOffset returns the absolute chunk coordinate embedded in an event.
func (m *GoEvtxMap) ChunkOffset() (int64, bool) {
	if m == nil {
		return 0, false
	}
	return coordinateFromMap(m, "ChunkOffset")
}

// EventOffset returns the chunk-relative event coordinate embedded in an event.
func (m *GoEvtxMap) EventOffset() (int64, bool) {
	if m == nil {
		return 0, false
	}
	return coordinateFromMap(m, "EventOffset", "RelativeOffset", "Offset")
}

type dirtySourceRegistry struct {
	mu      sync.Mutex
	sources map[string]*RecordDeduper
}

var openDirtySources = &dirtySourceRegistry{sources: make(map[string]*RecordDeduper)}

// OpenDirtyDeduper returns the process-wide cross-scan deduper for a path.
// The key is the absolute source path, not its size or modification time:
// appending records, repairing the dirty header or rewriting an equivalent
// serialization must not start a second identity generation, because that
// would republish every record already observed by a consumer.
func OpenDirtyDeduper(path string) *RecordDeduper {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if resolved, resolveErr := filepath.EvalSymlinks(abs); resolveErr == nil {
		abs = resolved
	}

	openDirtySources.mu.Lock()
	defer openDirtySources.mu.Unlock()
	if d, ok := openDirtySources.sources[abs]; ok {
		return d
	}
	d := NewDirtyDeduper().SetSource(abs)
	openDirtySources.sources[abs] = d
	return d
}

// ResetOpenDirtyDedupers clears process-wide cross-scan state. It is primarily
// useful for tests and long-running processes that want a fresh generation.
func ResetOpenDirtyDedupers() {
	openDirtySources.mu.Lock()
	openDirtySources.sources = make(map[string]*RecordDeduper)
	openDirtySources.mu.Unlock()
}

// ResetOpenDirtyDeduper clears the process-wide cross-scan frontier for one
// path. New scans of that source start with a fresh identity generation.
func ResetOpenDirtyDeduper(path string) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if resolved, resolveErr := filepath.EvalSymlinks(abs); resolveErr == nil {
		abs = resolved
	}
	openDirtySources.mu.Lock()
	for key := range openDirtySources.sources {
		if key == abs {
			delete(openDirtySources.sources, key)
		}
	}
	openDirtySources.mu.Unlock()
}

// RejectedRecords returns evidence from the deduper used by this File.
func (ef *File) RejectedRecords() []Rejection {
	ef.dedupMu.Lock()
	d := ef.Deduper
	ef.dedupMu.Unlock()
	if d == nil {
		return nil
	}
	return d.Rejected()
}

// Evidence accessor aliases for File consumers.
func (ef *File) Rejections() []Rejection         { return ef.RejectedRecords() }
func (ef *File) Rejects() []Rejection            { return ef.RejectedRecords() }
func (ef *File) RejectedEvents() []Rejection     { return ef.RejectedRecords() }
func (ef *File) RejectionEvidence() []Rejection  { return ef.RejectedRecords() }
func (ef *File) RejectEvidence() []Rejection     { return ef.RejectedRecords() }
func (ef *File) RejectedEvidence() []Rejection   { return ef.RejectedRecords() }
func (ef *File) Duplicates() []Rejection         { return ef.RejectedRecords() }
func (ef *File) DuplicateRecords() []Rejection   { return ef.RejectedRecords() }
func (ef *File) DuplicateEvents() []Rejection    { return ef.RejectedRecords() }
func (ef *File) DuplicateConflicts() []Rejection { return ef.RejectedRecords() }
func (ef *File) Conflicts() []Rejection          { return ef.RejectedRecords() }
func (ef *File) Evidence() []Rejection           { return ef.RejectedRecords() }
func (ef *File) GetRejectedRecords() []Rejection { return ef.RejectedRecords() }
func (ef *File) GetRejectedEvents() []Rejection  { return ef.RejectedRecords() }
func (ef *File) GetRejections() []Rejection      { return ef.RejectedRecords() }
func (ef *File) GetConflicts() []Rejection       { return ef.RejectedRecords() }
func (ef *File) GetDuplicates() []Rejection      { return ef.RejectedRecords() }
func (ef *File) DuplicateRecordIDs() []int64 {
	rs := ef.RejectedRecords()
	out := make([]int64, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.RecordID)
	}
	return out
}
func (ef *File) RejectedCount() int             { return len(ef.RejectedRecords()) }
func (ef *File) DuplicateCount() int            { return ef.RejectedCount() }
func (ef *File) ConflictCount() int             { return ef.RejectedCount() }
func (ef *File) GetDuplicateRecordIDs() []int64 { return ef.DuplicateRecordIDs() }
func (ef *File) GetDuplicateIDs() []int64       { return ef.DuplicateRecordIDs() }
func (ef *File) GetRejectedCount() int          { return ef.RejectedCount() }

// RejectedEventMaps returns decoded event maps retained as duplicate evidence.
func (ef *File) RejectedEventMaps() []*GoEvtxMap {
	rs := ef.RejectedRecords()
	out := make([]*GoEvtxMap, 0, len(rs))
	for _, r := range rs {
		if r.Event != nil {
			out = append(out, r.Event)
		}
	}
	return out
}
func (ef *File) RejectedMaps() []*GoEvtxMap       { return ef.RejectedEventMaps() }
func (ef *File) DuplicateEventMaps() []*GoEvtxMap { return ef.RejectedEventMaps() }

// AdmitEvent applies the File's identity frontier to one decoded event.
func (ef *File) AdmitEvent(event *GoEvtxMap) bool {
	d := ef.currentDeduper("File.AdmitEvent")
	_, ok := d.Admit(eventEnvelope{gem: event})
	return ok
}

// CheckEvent returns duplicate evidence and admission for one decoded event.
func (ef *File) CheckEvent(event *GoEvtxMap) (Rejection, bool) {
	d := ef.currentDeduper("File.CheckEvent")
	return d.Admit(eventEnvelope{gem: event})
}

// Deduplicate returns the admitted subset of events and retains duplicates in
// the File's evidence frontier.
func (ef *File) Deduplicate(events []*GoEvtxMap) []*GoEvtxMap {
	admitted, _ := ef.DeduplicateEvents(events)
	return admitted
}

// DeduplicateEvents returns admitted events and conflict evidence.
func (ef *File) DeduplicateEvents(events []*GoEvtxMap) ([]*GoEvtxMap, []Rejection) {
	d := ef.currentDeduper("File.DeduplicateEvents")
	out := make([]*GoEvtxMap, 0, len(events))
	for _, event := range events {
		if _, ok := d.Admit(eventEnvelope{gem: event}); ok {
			out = append(out, event)
		}
	}
	return out, d.Rejected()
}

// currentDeduper returns the File's existing identity frontier, creating one
// only when no stream has installed it yet. Unlike scanDeduper it never resets
// a non-OpenDirty frontier, so direct structured consumers accumulate identity
// evidence across calls.
func (ef *File) currentDeduper(stage string) *RecordDeduper {
	ef.dedupMu.Lock()
	defer ef.dedupMu.Unlock()
	if ef.Deduper == nil {
		ef.Deduper = NewRecordDeduper(stage).SetSource(ef.path)
	} else {
		ef.Deduper.SetStage(stage)
	}
	return ef.Deduper
}

// RecordDeduper returns the File's current identity frontier.
func (ef *File) RecordDeduper() *RecordDeduper {
	return ef.currentDeduper("RecordDeduper")
}

// DuplicateGuard and DeduperInstance are aliases for RecordDeduper.
func (ef *File) DuplicateGuard() *DuplicateGuard { return ef.RecordDeduper() }
func (ef *File) DeduperInstance() *RecordDeduper { return ef.RecordDeduper() }

// LastRejection returns the most recent conflict evidence, if any.
func (ef *File) LastRejection() (Rejection, bool) {
	rs := ef.RejectedRecords()
	if len(rs) == 0 {
		return Rejection{}, false
	}
	return rs[len(rs)-1], true
}

// FirstRejection returns the first conflict evidence, if any.
func (ef *File) FirstRejection() (Rejection, bool) {
	rs := ef.RejectedRecords()
	if len(rs) == 0 {
		return Rejection{}, false
	}
	return rs[0], true
}

func (ef *File) scanDeduper(stage string) *RecordDeduper {
	ef.dedupMu.Lock()
	defer ef.dedupMu.Unlock()

	if ef.CrossScanDeduplication {
		if ef.Deduper == nil {
			ef.Deduper = NewRecordDeduper(stage).SetSource(ef.path)
		}
		ef.Deduper.SetStage(stage)
		return ef.Deduper
	}

	d := NewRecordDeduper(stage).SetSource(ef.path)
	ef.Deduper = d
	return d
}
