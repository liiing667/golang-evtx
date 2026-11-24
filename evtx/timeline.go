package evtx

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/0xrawsec/golang-utils/log"
)

// Timeline ordering policy modes. They define how a TimelineGuard reacts when
// an event breaks the expected ordering of the public timeline.
const (
	// ModeWarn only emits an explicit warning through the logger when an
	// ordering anomaly is detected. Events are still delivered to consumers.
	ModeWarn = iota
	// ModeFailClosed drops the offending event so that no out-of-order event
	// ever reaches the consumers. A warning is logged for every dropped event.
	ModeFailClosed
	// ModeAbort stops the whole monitoring loop (MonitorEvents channel is
	// closed) as soon as an ordering anomaly is detected. This is the safest
	// option for pipelines that must never silently ingest an unordered event.
	ModeAbort
)

// Sentinel errors returned by TimelineGuard.Check.
var (
	// ErrTimelineRewind is returned when a new event carries an EventRecordID
	// lower than the last one already accepted on the timeline while its
	// timestamp is also in the past. It is the signature of a file reopen /
	// restart where the consumer would otherwise publish stale events in disk
	// order.
	ErrTimelineRewind = errors.New("timeline rewind: EventRecordID and TimeCreated both went backwards")
	// ErrEventRecordRegression is returned when the EventRecordID of a new
	// event is lower than the last accepted one while the timestamps stay
	// consistent. The record identity is the source of truth of the ordering,
	// so any regression of it is considered anomalous.
	ErrEventRecordRegression = errors.New("EventRecordID regression")
	// ErrTimeRegression is returned when the EventRecordID keeps advancing but
	// the TimeCreated of the event is strictly older than the last accepted
	// one. Same timestamps are legal (see TimelineGuard.Check) and never raise
	// this error.
	ErrTimeRegression = errors.New("TimeCreated regression")
	// ErrDuplicateRecord is returned when the same EventRecordID is seen twice
	// on the timeline with a different timestamp.
	ErrDuplicateRecord = errors.New("duplicate EventRecordID with conflicting timestamp")
)

// TimelineAnomaly describes a single ordering violation detected by a
// TimelineGuard. It binds together the two components of the timeline identity:
// the event timestamp (TimeCreated) and the record identity (EventRecordID).
type TimelineAnomaly struct {
	// Kind is the sentinel error describing the anomaly kind.
	Kind error
	// PrevRecordID is the last EventRecordID accepted before the anomaly.
	PrevRecordID int64
	// PrevTime is the last TimeCreated accepted before the anomaly.
	PrevTime time.Time
	// RecordID is the offending event EventRecordID.
	RecordID int64
	// Time is the offending event TimeCreated.
	Time time.Time
}

func (a TimelineAnomaly) Error() string {
	return fmt.Sprintf("%s: previous EventRecordID=%d TimeCreated=%s, "+
		"offending EventRecordID=%d TimeCreated=%s",
		a.Kind, a.PrevRecordID, a.PrevTime.UTC().Format(time.RFC3339Nano),
		a.RecordID, a.Time.UTC().Format(time.RFC3339Nano))
}

// TimelineGuard enforces the ordering of the public event timeline. The
// timeline is defined by two coupled attributes of every event:
//
//   - the record identity: EventRecordID (/Event/System/EventRecordID)
//   - the event timestamp: TimeCreated (/Event/System/TimeCreated/SystemTime)
//
// A healthy timeline is monotonically non decreasing on both attributes:
//
//   - equal timestamps are perfectly legal (several events can be written
//     within the same filetime tick), they never trigger an anomaly;
//   - equal EventRecordID values are tolerated only when the timestamps match
//     too, i.e. the exact same event is published twice (re-read after a
//     reopen);
//   - any strict regression of the EventRecordID, or a timestamp going into
//     the past while records keep advancing, is reported as an anomaly.
//
// The guard explicitly distinguishes a legitimate stream reset (file rotate /
// reopen where both identities restart together and go backwards, which is the
// common case described in issue UID 39239) from in-stream corruption.
type TimelineGuard struct {
	sync.Mutex
	mode         int
	initialized  bool
	lastRecordID int64
	lastTime     time.Time
	rewindCount  uint64
	droppedCount uint64
}

// NewTimelineGuard initializes a TimelineGuard using the given policy mode
// (ModeWarn, ModeFailClosed or ModeAbort).
func NewTimelineGuard(mode int) *TimelineGuard {
	return &TimelineGuard{mode: mode}
}

// Mode returns the policy mode currently in use.
func (g *TimelineGuard) Mode() int {
	return g.mode
}

// RewindCount returns the number of timeline rewinds detected so far, i.e.
// events whose EventRecordID and TimeCreated both went backwards at the same
// time (file reopen / restart signature).
func (g *TimelineGuard) RewindCount() uint64 {
	g.Lock()
	defer g.Unlock()
	return g.rewindCount
}

// DroppedCount returns the number of events rejected in ModeFailClosed because
// of an ordering anomaly.
func (g *TimelineGuard) DroppedCount() uint64 {
	g.Lock()
	defer g.Unlock()
	return g.droppedCount
}

// Check verifies that the event identified by its EventRecordID and TimeCreated
// can be appended to the public timeline. It returns the detected anomaly
// (nil when the event is in order) and a boolean telling whether the caller
// must stop delivering events entirely (true only in ModeAbort).
//
// Events missing a TimeCreated or an EventRecordID are accepted untouched: the
// guard cannot take an ordering decision without the two identity attributes.
func (g *TimelineGuard) Check(recordID int64, t time.Time) (anomaly *TimelineAnomaly, abort bool) {
	g.Lock()
	defer g.Unlock()

	// Without the two identity attributes we cannot bind the event to the
	// timeline: let it through instead of taking a random decision.
	if t.IsZero() || recordID == 0 {
		return nil, false
	}

	if !g.initialized {
		g.initialized = true
		g.lastRecordID = recordID
		g.lastTime = t
		return nil, false
	}

	var kind error
	switch {
	case recordID < g.lastRecordID && t.Before(g.lastTime):
		// Both identities go backwards together: this is the unmistakable
		// signature of a file reopen / rotation replaying events in disk order.
		kind = ErrTimelineRewind
		g.rewindCount++
	case recordID < g.lastRecordID:
		// Record identity regresses while time does not: in-stream corruption
		// or overlapping chunks.
		kind = ErrEventRecordRegression
	case recordID == g.lastRecordID && !t.Equal(g.lastTime):
		// Same record id reused with a different timestamp cannot be legal.
		kind = ErrDuplicateRecord
	case recordID == g.lastRecordID:
		// Exact same event re-read (reopen of an already consumed file): legal.
		return nil, false
	case t.Before(g.lastTime):
		// Records still advance but the timestamp moves into the past. Equal
		// timestamps are legal and handled by time.Time.Before returning false.
		kind = ErrTimeRegression
	}

	if kind == nil {
		// Event is in order: advance the timeline.
		g.lastRecordID = recordID
		g.lastTime = t
		return nil, false
	}

	anomaly = &TimelineAnomaly{
		Kind:         kind,
		PrevRecordID: g.lastRecordID,
		PrevTime:     g.lastTime,
		RecordID:     recordID,
		Time:         t,
	}

	switch g.mode {
	case ModeFailClosed:
		g.droppedCount++
		log.Warnf("timeline guard (fail-closed): %s", anomaly)
		return anomaly, false
	case ModeAbort:
		log.Errorf("timeline guard (abort): %s", anomaly)
		return anomaly, true
	default: // ModeWarn
		log.Warnf("timeline guard (warn): %s", anomaly)
		// In warn mode the event is still delivered: advance the timeline so
		// that subsequent checks compare against the newest observation.
		g.lastRecordID = recordID
		g.lastTime = t
		return anomaly, false
	}
}

// CheckEvent is a convenience wrapper around Check which extracts the
// EventRecordID and TimeCreated directly from a GoEvtxMap event. Parsing errors
// on those attributes make the event pass through unchecked.
func (g *TimelineGuard) CheckEvent(e *GoEvtxMap) (anomaly *TimelineAnomaly, abort bool) {
	recordID, err := e.GetInt(&EventRecordIDPath)
	if err != nil {
		return nil, false
	}
	t, err := e.GetTime(&SystemTimePath)
	if err != nil {
		return nil, false
	}
	return g.Check(recordID, t)
}

// Reset clears the timeline state. It can be used by consumers that want to
// start a fresh timeline on demand, for instance after an explicit file
// rotation handled out of band.
func (g *TimelineGuard) Reset() {
	g.Lock()
	defer g.Unlock()
	g.initialized = false
	g.lastRecordID = 0
	g.lastTime = time.Time{}
	g.rewindCount = 0
	g.droppedCount = 0
}
