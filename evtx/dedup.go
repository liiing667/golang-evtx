package evtx

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// Errors used when a record identity cannot be admitted into a public event
// stream. They are aliases so callers can use the name that best matches the
// vocabulary of their consumer while errors.Is keeps working.
var (
	ErrDuplicateEventRecordID = errors.New("duplicate EventRecordID")
	ErrDuplicateEventRecord   = ErrDuplicateEventRecordID
	ErrDuplicateRecordID      = ErrDuplicateEventRecordID
	ErrDuplicateRecord        = ErrDuplicateEventRecordID
	ErrRecordIdentityConflict = ErrDuplicateEventRecordID
)

// RecordIdentity is the stable identity of an EVTX record plus the source
// coordinates at which it was observed. The numeric EventRecordID is the
// deduplication key; offsets and timestamps are evidence only.
type RecordIdentity struct {
	// EventRecordID is the identity used by the Windows event log format.
	EventRecordID int64 `json:"EventRecordID"`
	// RecordID and ID are convenience aliases for EventRecordID.
	RecordID int64 `json:"record_id"`
	ID       int64 `json:"id"`

	// HeaderRecordID is the value read from the fixed-size event header.
	HeaderRecordID int64 `json:"header_record_id,omitempty"`
	// PayloadRecordID is the value decoded from Event/System/EventRecordID.
	PayloadRecordID int64 `json:"payload_record_id,omitempty"`

	Timestamp time.Time `json:"timestamp,omitempty"`

	// Source identifies the File/path/reader and parsing stage.
	Source string `json:"source,omitempty"`
	Stage  string `json:"stage,omitempty"`

	// ChunkOffset is the absolute file offset of the containing chunk.
	ChunkOffset int64 `json:"chunk_offset,omitempty"`
	// Offset is the event offset relative to ChunkOffset, matching Event.Offset.
	Offset int64 `json:"offset,omitempty"`
	// EventOffset and RelativeOffset are aliases for Offset.
	EventOffset    int64 `json:"event_offset,omitempty"`
	RelativeOffset int64 `json:"relative_offset,omitempty"`
	// AbsoluteOffset is ChunkOffset + Offset.
	AbsoluteOffset int64 `json:"absolute_offset,omitempty"`
	FileOffset     int64 `json:"file_offset,omitempty"`
}

// Rejection is the evidence retained for a record that was not published by a
// deduplicating public event stream. It intentionally keeps both the decoded
// event and its binary/source coordinates so an investigator can review the
// conflict without trusting the stream's deduplicated output alone.
type Rejection struct {
	// Identity is the identity of the rejected observation.
	Identity RecordIdentity `json:"identity"`

	// Flat identity fields make assertions and JSON reports convenient.
	// EventRecordIDValue is serialized with the canonical EVTX key. Callers
	// that treat evidence as event-like should use EventRecordID().
	EventRecordIDValue int64 `json:"EventRecordID"`
	RecordID           int64 `json:"record_id"`
	ID                 int64 `json:"id"`

	// Kind/Err is the stable error taxonomy. Reason is a human-readable string.
	Kind   error  `json:"-"`
	Err    error  `json:"-"`
	Reason string `json:"reason"`
	// ErrorMessage is a string alias for callers that prefer that field name.
	ErrorMessage string `json:"error_message,omitempty"`
	Code         string `json:"code,omitempty"`
	Type         string `json:"type,omitempty"`
	// ConflictType is a descriptive alias used by forensic consumers.
	ConflictType string `json:"conflict_type,omitempty"`

	Stage          string `json:"stage"`
	Phase          string `json:"phase,omitempty"`
	Source         string `json:"source,omitempty"`
	Origin         string `json:"origin,omitempty"`
	SourceIdentity string `json:"source_identity,omitempty"`

	// Event is the fully decoded public event, when decoding succeeded.
	Event *GoEvtxMap `json:"event,omitempty"`
	// Map is an alias for Event.
	Map *GoEvtxMap `json:"map,omitempty"`
	// Object/CurrentObject are aliases for the retained current object.
	Object        *GoEvtxMap `json:"object,omitempty"`
	CurrentObject *GoEvtxMap `json:"current_object,omitempty"`
	// Record is the fixed-header record and offset information.
	Record Event `json:"record,omitempty"`

	// FirstEvent/FirstRecord optionally retain the accepted observation in a
	// conflict. The stream reparses it from source coordinates on demand, so
	// ordinary unique-event processing does not retain every event map.
	FirstEvent  *GoEvtxMap `json:"first_event,omitempty"`
	FirstMap    *GoEvtxMap `json:"first_map,omitempty"`
	FirstObject *GoEvtxMap `json:"first_object,omitempty"`
	FirstRecord Event      `json:"first_record,omitempty"`
	// First is the complete identity/coordinate tuple of the accepted record.
	First RecordIdentity `json:"first"`
	// Existing/AcceptedEvent alias FirstEvent.
	Existing      *GoEvtxMap `json:"existing,omitempty"`
	AcceptedEvent *GoEvtxMap `json:"accepted_event,omitempty"`

	// Coordinates of the rejected observation.
	ChunkOffset    int64 `json:"chunk_offset,omitempty"`
	Offset         int64 `json:"offset,omitempty"`
	EventOffset    int64 `json:"event_offset,omitempty"`
	AbsoluteOffset int64 `json:"absolute_offset,omitempty"`
	FileOffset     int64 `json:"file_offset,omitempty"`

	// Coordinates of the first admitted observation with the same identity.
	FirstChunkOffset    int64 `json:"first_chunk_offset,omitempty"`
	FirstOffset         int64 `json:"first_offset,omitempty"`
	FirstAbsoluteOffset int64 `json:"first_absolute_offset,omitempty"`
	FirstFileOffset     int64 `json:"first_file_offset,omitempty"`

	// Occurrences is the number of observations seen for this ID including
	// this rejection. RejectionNumber is the duplicate ordinal.
	Occurrences     int       `json:"occurrences"`
	RejectionNumber int       `json:"rejection_number"`
	Index           int       `json:"index"`
	DetectedAt      time.Time `json:"detected_at"`
	Timestamp       time.Time `json:"timestamp"`
	FirstSeenAt     time.Time `json:"first_seen_at,omitempty"`
}

// Error implements error for a rejection.
func (r Rejection) Error() string {
	if r.Reason != "" {
		return fmt.Sprintf("%s: EventRecordID=%d at %s", r.Reason, r.RecordID, r.location())
	}
	if r.Kind != nil {
		return fmt.Sprintf("%s: EventRecordID=%d at %s", r.Kind, r.RecordID, r.location())
	}
	return fmt.Sprintf("rejected EventRecordID=%d at %s", r.RecordID, r.location())
}

// Unwrap exposes the taxonomy sentinel to errors.Is/errors.As.
func (r Rejection) Unwrap() error {
	if r.Kind != nil {
		return r.Kind
	}
	return r.Err
}

// EventRecordID returns the canonical record id. This keeps rejection
// evidence event-like for consumers that already call GoEvtxMap.EventRecordID.
func (r Rejection) EventRecordID() int64 { return r.RecordID }

// EventRecordIDValue gives callers an explicit accessor alias.
func (r Rejection) EventRecordIDValueMethod() int64 { return r.RecordID }

// TimeCreated delegates to the retained event when available and otherwise
// returns the timestamp stored in identity evidence.
func (r Rejection) TimeCreated() time.Time {
	if r.Event != nil {
		if t, err := r.Event.GetTime(&SystemTimePath); err == nil {
			return t
		}
	}
	if !r.Identity.Timestamp.IsZero() {
		return r.Identity.Timestamp
	}
	return time.Time{}
}

// GoEvtxMapValue returns the decoded event retained as evidence.
func (r Rejection) GoEvtxMapValue() *GoEvtxMap { return r.Event }

func (r Rejection) location() string {
	return locationString(r.Source, r.AbsoluteOffset, r.Offset)
}

// Location returns a source-coordinate description of the identity.
func (i RecordIdentity) Location() string {
	return locationString(i.Source, i.AbsoluteOffset, i.Offset)
}

func locationString(source string, absolute, offset int64) string {
	switch {
	case absolute != 0:
		return fmt.Sprintf("%s@0x%x", source, absolute)
	case offset != 0:
		return fmt.Sprintf("%s+0x%x", source, offset)
	case source != "":
		return source
	default:
		return "unknown-source"
	}
}

// The following aliases allow caller/contract vocabulary to remain stable
// while the core evidence type stays one concrete structure.
type (
	RejectedEvent     = Rejection
	RejectedRecord    = Rejection
	RejectRecord      = Rejection
	RejectionEvidence = Rejection
	RejectEvidence    = Rejection
	RecordConflict    = Rejection
	ConflictEvidence  = Rejection
	DuplicateRecord   = Rejection
	DuplicateEvent    = Rejection
	DuplicateEvidence = Rejection
	DuplicateConflict = Rejection
	DuplicateID       = Rejection
)

// RecordDeduper is the single identity decision frontier used by every public
// event stream. A new deduper is created for each stream traversal so reopening
// or re-running a stream does not suppress a complete legitimate scan.
type RecordDeduper struct {
	mu         sync.Mutex
	stage      string
	source     string
	seen       map[int64]RecordIdentity
	counts     map[int64]int
	rejected   []Rejection
	hooks      []func(Rejection)
	loadRecord func(RecordIdentity) (Event, *GoEvtxMap)
}

// Deduper and guard aliases cover common naming conventions.
type (
	Deduper            = RecordDeduper
	DuplicateGuard     = RecordDeduper
	RecordGuard        = RecordDeduper
	RecordDeduplicator = RecordDeduper
)

// NewRecordDeduper creates a deduper. The optional stage is used in evidence.
func NewRecordDeduper(stage ...string) *RecordDeduper {
	d := &RecordDeduper{
		seen:   make(map[int64]RecordIdentity),
		counts: make(map[int64]int),
	}
	if len(stage) > 0 {
		d.stage = stage[0]
	}
	return d
}

// NewDeduper and NewEventDeduplicator are friendly constructor aliases.
func NewDeduper(stage ...string) *RecordDeduper { return NewRecordDeduper(stage...) }
func NewEventDeduplicator(stage ...string) *RecordDeduper {
	return NewRecordDeduper(stage...)
}
func NewRecordDeduplicator(stage ...string) *RecordDeduper {
	return NewRecordDeduper(stage...)
}
func NewDuplicateGuard(stage ...string) *DuplicateGuard {
	return NewRecordDeduper(stage...)
}

// DeduplicateEvents applies record-identity deduplication to a structured
// event slice and returns the admitted events plus rejection evidence.
func DeduplicateEvents(events []*GoEvtxMap) ([]*GoEvtxMap, []Rejection) {
	d := NewRecordDeduper("DeduplicateEvents")
	out := make([]*GoEvtxMap, 0, len(events))
	for _, event := range events {
		if d.AdmitEvent(event) {
			out = append(out, event)
		}
	}
	return out, d.Rejected()
}

// DeduplicateWithEvidence returns admitted events and conflict evidence.
func DeduplicateWithEvidence(events []*GoEvtxMap) ([]*GoEvtxMap, []Rejection) {
	return DeduplicateEvents(events)
}

// Deduplicate and UniqueEvents return only the admitted events.
func Deduplicate(events []*GoEvtxMap) []*GoEvtxMap {
	out, _ := DeduplicateEvents(events)
	return out
}

func DedupEvents(events []*GoEvtxMap) ([]*GoEvtxMap, []Rejection) {
	return DeduplicateEvents(events)
}

func UniqueEvents(events []*GoEvtxMap) []*GoEvtxMap {
	out, _ := DeduplicateEvents(events)
	return out
}

// SetStage labels subsequent evidence with the public entry point.
func (d *RecordDeduper) SetStage(stage string) *RecordDeduper {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stage = stage
	return d
}

// SetSource labels subsequent evidence with the file/reader source.
func (d *RecordDeduper) SetSource(source string) *RecordDeduper {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.source = source
	return d
}

// OnRejection registers an observation hook. Hooks are invoked outside the
// deduper lock and may call its read accessors.
func (d *RecordDeduper) OnRejection(h func(Rejection)) *RecordDeduper {
	if h == nil {
		return d
	}
	d.mu.Lock()
	d.hooks = append(d.hooks, h)
	d.mu.Unlock()
	return d
}

// SetRecordLoader installs a source-coordinate loader used to include the
// accepted first observation in conflict evidence.
func (d *RecordDeduper) SetRecordLoader(loader func(RecordIdentity) (Event, *GoEvtxMap)) *RecordDeduper {
	d.mu.Lock()
	d.loadRecord = loader
	d.mu.Unlock()
	return d
}

// Seen reports whether id has already been admitted.
func (d *RecordDeduper) Seen(id int64) bool {
	if d == nil || id == 0 {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.seen[id]
	return ok
}

// AdmitID admits a bare identity. It returns false for a duplicate non-zero ID.
func (d *RecordDeduper) AdmitID(id int64) bool {
	if d == nil || id == 0 {
		return true
	}
	_, admitted := d.Admit(eventEnvelope{event: Event{Header: EventHeader{ID: id}}})
	return admitted
}

// AdmitEvent admits a decoded event using its EventRecordID. It is primarily a
// convenience for tests and structured consumers.
func (d *RecordDeduper) AdmitEvent(event *GoEvtxMap) bool {
	_, admitted := d.Admit(eventEnvelope{gem: event})
	return admitted
}

// Check returns the retained rejection and true when the event is admitted.
func (d *RecordDeduper) Check(event *GoEvtxMap) (Rejection, bool) {
	return d.Admit(eventEnvelope{gem: event})
}

// Admit applies the canonical identity rule and retains evidence on conflict.
// The returned bool is true when the envelope may be published.
func (d *RecordDeduper) Admit(env eventEnvelope) (Rejection, bool) {
	if d == nil {
		return Rejection{}, true
	}

	identity := env.identity(d.stage, d.source)
	if identity.RecordID == 0 {
		// Synthetic/raw records without a readable identity preserve the
		// historical pass-through behavior.
		return Rejection{}, true
	}

	d.mu.Lock()

	id := identity.RecordID
	d.counts[id]++
	count := d.counts[id]

	if count == 1 {
		identity.Stage = d.stage
		identity.Source = firstNonEmpty(identity.Source, d.source)
		d.seen[id] = identity
		d.mu.Unlock()
		return Rejection{}, true
	}

	first := d.seen[id]
	now := time.Now()
	var firstRecord Event
	var firstEvent *GoEvtxMap
	if d.loadRecord != nil {
		firstRecord, firstEvent = d.loadRecord(first)
	}
	r := Rejection{
		Identity:            identity,
		EventRecordIDValue:  id,
		RecordID:            id,
		ID:                  id,
		Kind:                ErrDuplicateEventRecordID,
		Err:                 ErrDuplicateEventRecordID,
		Reason:              ErrDuplicateEventRecordID.Error(),
		ErrorMessage:        ErrDuplicateEventRecordID.Error(),
		Code:                "duplicate_event_record_id",
		Type:                "duplicate_record_identity",
		ConflictType:        "duplicate_event_record_id",
		Stage:               firstNonEmpty(identity.Stage, d.stage),
		Phase:               firstNonEmpty(identity.Stage, d.stage),
		Source:              firstNonEmpty(identity.Source, d.source),
		Origin:              firstNonEmpty(identity.Source, d.source),
		SourceIdentity:      identity.Location(),
		Event:               env.gem,
		Map:                 env.gem,
		Object:              env.gem,
		CurrentObject:       env.gem,
		Record:              env.event,
		FirstEvent:          firstEvent,
		FirstMap:            firstEvent,
		FirstObject:         firstEvent,
		FirstRecord:         firstRecord,
		First:               first,
		Existing:            firstEvent,
		AcceptedEvent:       firstEvent,
		ChunkOffset:         identity.ChunkOffset,
		Offset:              identity.Offset,
		EventOffset:         identity.EventOffset,
		AbsoluteOffset:      identity.AbsoluteOffset,
		FileOffset:          identity.FileOffset,
		FirstChunkOffset:    first.ChunkOffset,
		FirstOffset:         first.Offset,
		FirstAbsoluteOffset: first.AbsoluteOffset,
		FirstFileOffset:     first.FileOffset,
		Occurrences:         count,
		RejectionNumber:     count - 1,
		Index:               len(d.rejected),
		DetectedAt:          now,
		Timestamp:           now,
		FirstSeenAt:         now,
	}
	d.rejected = append(d.rejected, r)
	hooks := append([]func(Rejection){}, d.hooks...)
	d.mu.Unlock()
	for _, hook := range hooks {
		hook(r)
	}
	return r, false
}

// Rejected returns a defensive copy of all retained conflict evidence.
func (d *RecordDeduper) Rejected() []Rejection {
	if d == nil {
		return []Rejection{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Rejection, len(d.rejected))
	copy(out, d.rejected)
	return out
}

// Rejections and Conflicts are vocabulary aliases for Rejected.
func (d *RecordDeduper) Rejections() []Rejection         { return d.Rejected() }
func (d *RecordDeduper) Rejects() []Rejection            { return d.Rejected() }
func (d *RecordDeduper) RejectedRecords() []Rejection    { return d.Rejected() }
func (d *RecordDeduper) RejectedEvents() []Rejection     { return d.Rejected() }
func (d *RecordDeduper) RejectionEvidence() []Rejection  { return d.Rejected() }
func (d *RecordDeduper) RejectEvidence() []Rejection     { return d.Rejected() }
func (d *RecordDeduper) RejectedEvidence() []Rejection   { return d.Rejected() }
func (d *RecordDeduper) DuplicateEvidence() []Rejection  { return d.Rejected() }
func (d *RecordDeduper) Conflicts() []Rejection          { return d.Rejected() }
func (d *RecordDeduper) DuplicateConflicts() []Rejection { return d.Rejected() }
func (d *RecordDeduper) Duplicates() []Rejection         { return d.Rejected() }
func (d *RecordDeduper) DuplicateRecords() []Rejection   { return d.Rejected() }
func (d *RecordDeduper) DuplicateEvents() []Rejection    { return d.Rejected() }

// RejectedMaps returns only the decoded event maps retained as evidence.
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

// Count returns the number of rejected duplicate observations.
func (d *RecordDeduper) Count() int {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.rejected)
}

// RejectedCount, ConflictCount and DuplicateCount are count aliases.
func (d *RecordDeduper) RejectedCount() int  { return d.Count() }
func (d *RecordDeduper) ConflictCount() int  { return d.Count() }
func (d *RecordDeduper) DuplicateCount() int { return d.Count() }

// IDs returns the duplicate record IDs in rejection order.
func (d *RecordDeduper) IDs() []int64 {
	rs := d.Rejected()
	out := make([]int64, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.RecordID)
	}
	return out
}

func (d *RecordDeduper) DuplicateRecordIDs() []int64 { return d.IDs() }
func (d *RecordDeduper) DuplicateIDs() []int64       { return d.IDs() }

// Reset clears all identity and evidence state.
func (d *RecordDeduper) Reset() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = make(map[int64]RecordIdentity)
	d.counts = make(map[int64]int)
	d.rejected = nil
}

// eventEnvelope carries the binary header coordinates together with the
// decoded public map through the stream-level identity frontier.
type eventEnvelope struct {
	event       Event
	gem         *GoEvtxMap
	chunkOffset int64
}

func (env eventEnvelope) identity(stage, source string) RecordIdentity {
	headerID := env.event.Header.ID
	payloadID, payloadOK := recordIDFromMap(env.gem)

	id := headerID
	if id == 0 && payloadOK {
		id = payloadID
	}

	offset := env.event.Offset
	absolute := env.chunkOffset + offset
	identity := RecordIdentity{
		EventRecordID:   id,
		RecordID:        id,
		ID:              id,
		HeaderRecordID:  headerID,
		PayloadRecordID: payloadID,
		Stage:           stage,
		Source:          source,
		ChunkOffset:     env.chunkOffset,
		Offset:          offset,
		EventOffset:     offset,
		RelativeOffset:  offset,
		AbsoluteOffset:  absolute,
		FileOffset:      absolute,
	}

	if env.event.Header.Timestamp.Nanoseconds != 0 {
		identity.Timestamp = time.Time(env.event.Header.Timestamp.Time())
	} else if env.gem != nil {
		if t, err := env.gem.GetTime(&SystemTimePath); err == nil {
			identity.Timestamp = t
		}
	}
	return identity
}

func recordIDFromMap(gem *GoEvtxMap) (int64, bool) {
	if gem == nil {
		return 0, false
	}

	paths := []GoEvtxPath{
		EventRecordIDPath,
		Path("/Event/System/EventRecordID/Value"),
	}
	for _, p := range paths {
		v, err := gem.Get(&p)
		if err != nil || v == nil {
			continue
		}
		if id, ok := coerceRecordID(*v); ok {
			return id, true
		}
	}
	return 0, false
}

func coerceRecordID(v interface{}) (int64, bool) {
	switch x := v.(type) {
	case nil:
		return 0, false
	case string:
		if id, err := strconv.ParseInt(x, 10, 64); err == nil {
			return id, true
		}
		id, err := strconv.ParseInt(x, 0, 64)
		return id, err == nil
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
	case uintptr:
		return int64(x), true
	case float32:
		return int64(x), true
	case float64:
		return int64(x), true
	case json.Number:
		id, err := x.Int64()
		return id, err == nil
	case GoEvtxMap:
		for _, key := range []string{"Value", "value", "#text", "text"} {
			if inner, ok := x[key]; ok {
				if id, ok := coerceRecordID(inner); ok {
					return id, true
				}
			}
		}
	case map[string]interface{}:
		for _, key := range []string{"Value", "value", "#text", "text"} {
			if inner, ok := x[key]; ok {
				if id, ok := coerceRecordID(inner); ok {
					return id, true
				}
			}
		}
	case fmt.Stringer:
		s := x.String()
		if id, err := strconv.ParseInt(s, 10, 64); err == nil {
			return id, true
		}
		id, err := strconv.ParseInt(s, 0, 64)
		return id, err == nil
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

func (ef *File) sourceName() string {
	if ef != nil && ef.path != "" {
		return ef.path
	}
	return "io.ReadSeeker"
}

func (ef *File) newDeduper(stage string) *RecordDeduper {
	d := NewRecordDeduper(stage).SetSource(ef.sourceName())
	d.SetRecordLoader(ef.loadRecordEvidence)
	ef.dedupMu.Lock()
	ef.deduper = d
	ef.dedupMu.Unlock()
	return d
}

func (ef *File) loadRecordEvidence(id RecordIdentity) (Event, *GoEvtxMap) {
	if ef == nil || id.Offset <= 0 {
		return Event{}, nil
	}
	chunk, err := ef.FetchChunk(id.ChunkOffset)
	if err != nil {
		return Event{}, nil
	}
	event := chunk.ParseEvent(id.Offset)
	gem, err := event.GoEvtxMap(&chunk)
	if err != nil || gem == nil {
		return event, nil
	}
	return event, gem
}

// Deduper returns the identity/evidence collector used by the most recent
// event stream invocation on this File.
func (ef *File) Deduper() *RecordDeduper {
	ef.dedupMu.Lock()
	defer ef.dedupMu.Unlock()
	if ef.deduper == nil {
		ef.deduper = NewRecordDeduper().SetSource(ef.sourceName())
	}
	return ef.deduper
}

// DuplicateGuard and RecordDeduper are accessor aliases for Deduper.
func (ef *File) DuplicateGuard() *DuplicateGuard { return ef.Deduper() }
func (ef *File) RecordDeduper() *RecordDeduper   { return ef.Deduper() }

// AdmitEvent applies the File's latest/current identity frontier to a
// structured event. It is primarily useful for tests and custom consumers.
func (ef *File) AdmitEvent(event *GoEvtxMap) bool {
	return ef.Deduper().AdmitEvent(event)
}

// CheckEvent returns rejection evidence and admission result for event.
func (ef *File) CheckEvent(event *GoEvtxMap) (Rejection, bool) {
	return ef.Deduper().Check(event)
}

// Deduplicate returns the admitted subset of events and retains conflicts in
// the File's evidence collector.
func (ef *File) Deduplicate(events []*GoEvtxMap) []*GoEvtxMap {
	d := ef.Deduper()
	out := make([]*GoEvtxMap, 0, len(events))
	for _, event := range events {
		if d.AdmitEvent(event) {
			out = append(out, event)
		}
	}
	return out
}

// RejectedRecords returns duplicate/conflict evidence from the latest stream.
func (ef *File) RejectedRecords() []Rejection { return ef.Deduper().Rejected() }

// Rejections, RejectedEvents and RejectionEvidence are evidence accessors.
func (ef *File) Rejections() []Rejection              { return ef.RejectedRecords() }
func (ef *File) Rejects() []Rejection                 { return ef.RejectedRecords() }
func (ef *File) RejectedEvents() []RejectedEvent      { return ef.RejectedRecords() }
func (ef *File) RejectionEvidence() []Rejection       { return ef.RejectedRecords() }
func (ef *File) RejectEvidence() []Rejection          { return ef.RejectedRecords() }
func (ef *File) RejectedEvidence() []Rejection        { return ef.RejectedRecords() }
func (ef *File) DuplicateEvidence() []Rejection       { return ef.RejectedRecords() }
func (ef *File) Evidence() []Rejection                { return ef.RejectedRecords() }
func (ef *File) Conflicts() []RecordConflict          { return ef.RejectedRecords() }
func (ef *File) DuplicateConflicts() []RecordConflict { return ef.RejectedRecords() }
func (ef *File) Duplicates() []DuplicateRecord        { return ef.RejectedRecords() }
func (ef *File) DuplicateRecords() []RejectedRecord   { return ef.RejectedRecords() }
func (ef *File) DuplicateEvents() []DuplicateEvent    { return ef.RejectedRecords() }

// RejectedEventMaps returns decoded event maps retained by the latest stream.
func (ef *File) RejectedEventMaps() []*GoEvtxMap  { return ef.Deduper().RejectedMaps() }
func (ef *File) RejectedMaps() []*GoEvtxMap       { return ef.Deduper().RejectedMaps() }
func (ef *File) DuplicateEventMaps() []*GoEvtxMap { return ef.Deduper().RejectedMaps() }

// Count accessors.
func (ef *File) RejectedCount() int  { return ef.Deduper().Count() }
func (ef *File) ConflictCount() int  { return ef.Deduper().Count() }
func (ef *File) DuplicateCount() int { return ef.Deduper().Count() }

// DuplicateRecordIDs returns duplicate IDs from the latest stream.
func (ef *File) DuplicateRecordIDs() []int64 { return ef.Deduper().IDs() }
func (ef *File) DuplicateIDs() []int64       { return ef.Deduper().IDs() }

// Get-prefixed aliases for consumers that prefer that naming style.
func (ef *File) GetRejectedRecords() []Rejection { return ef.RejectedRecords() }
func (ef *File) GetRejectedEvents() []RejectedEvent {
	return ef.RejectedEvents()
}
func (ef *File) GetRejections() []Rejection       { return ef.Rejections() }
func (ef *File) GetConflicts() []RecordConflict   { return ef.Conflicts() }
func (ef *File) GetDuplicates() []DuplicateRecord { return ef.Duplicates() }
func (ef *File) GetDuplicateRecordIDs() []int64   { return ef.DuplicateRecordIDs() }
func (ef *File) GetDuplicateIDs() []int64         { return ef.DuplicateIDs() }
func (ef *File) GetRejectedCount() int            { return ef.RejectedCount() }

// LastRejection returns the most recent conflict evidence and whether one exists.
func (ef *File) LastRejection() (Rejection, bool) {
	rs := ef.RejectedRecords()
	if len(rs) == 0 {
		return Rejection{}, false
	}
	return rs[len(rs)-1], true
}

// FirstRejection returns the first conflict evidence and whether one exists.
func (ef *File) FirstRejection() (Rejection, bool) {
	rs := ef.RejectedRecords()
	if len(rs) == 0 {
		return Rejection{}, false
	}
	return rs[0], true
}
