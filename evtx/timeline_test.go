package evtx

import (
	"strconv"
	"testing"
	"time"
)

// base is an arbitrary fixed timestamp used by all the tests.
var base = time.Date(2026, 11, 25, 8, 0, 0, 0, time.UTC)

func mkEvent(recordID int64, t time.Time) *GoEvtxMap {
	e := make(GoEvtxMap)
	sys := GoEvtxMap{
		"EventRecordID": recordIDString(recordID),
		"TimeCreated":   GoEvtxMap{"SystemTime": t},
	}
	e["Event"] = GoEvtxMap{"System": sys}
	return &e
}

func recordIDString(id int64) string {
	// GoEvtxMap.GetInt parses string values, which is the representation
	// produced by the BinXML parser for EventRecordID.
	return strconv.FormatInt(id, 10)
}

func TestTimelineGuardMonotonicAndEqualTimestamps(t *testing.T) {
	g := NewTimelineGuard(ModeFailClosed)

	// Strictly monotonic stream: must pass untouched.
	for i := int64(1); i <= 10; i++ {
		if a, abort := g.Check(i, base.Add(time.Duration(i)*time.Second)); a != nil || abort {
			t.Fatalf("monotonic event %d rejected: %v abort=%v", i, a, abort)
		}
	}

	// Several events sharing the exact same timestamp are legal (filetime tick
	// granularity), as long as the record identity keeps advancing.
	same := base.Add(11 * time.Second)
	for i := int64(11); i <= 15; i++ {
		if a, abort := g.Check(i, same); a != nil || abort {
			t.Fatalf("equal-timestamp event %d rejected: %v abort=%v", i, a, abort)
		}
	}

	if g.DroppedCount() != 0 || g.RewindCount() != 0 {
		t.Fatalf("expected no anomaly, got dropped=%d rewinds=%d", g.DroppedCount(), g.RewindCount())
	}
}

func TestTimelineGuardReopenRewindFailClosed(t *testing.T) {
	g := NewTimelineGuard(ModeFailClosed)

	// Initial healthy stream.
	g.Check(100, base)
	g.Check(101, base.Add(time.Second))

	// File reopen: events are replayed in disk order, record id and timestamp
	// both go backwards.
	a, abort := g.Check(1, base.Add(-time.Hour))
	if a == nil || a.Kind != ErrTimelineRewind {
		t.Fatalf("expected ErrTimelineRewind, got %v", a)
	}
	if abort {
		t.Fatal("fail-closed mode must not abort the stream")
	}
	if g.DroppedCount() != 1 || g.RewindCount() != 1 {
		t.Fatalf("expected 1 dropped and 1 rewind, got dropped=%d rewind=%d",
			g.DroppedCount(), g.RewindCount())
	}

	// The timeline anchor must not move after a dropped event: a healthy event
	// following the replayed junk is still compared against record 101.
	a, _ = g.Check(102, base.Add(2*time.Second))
	if a != nil {
		t.Fatalf("healthy event after rewind was rejected: %v", a)
	}
}

func TestTimelineGuardReopenRewindWarn(t *testing.T) {
	g := NewTimelineGuard(ModeWarn)
	g.Check(100, base)

	a, abort := g.Check(1, base.Add(-time.Hour))
	if a == nil || a.Kind != ErrTimelineRewind || abort {
		t.Fatalf("warn mode: expected non-aborting rewind anomaly, got %v abort=%v", a, abort)
	}
	if g.DroppedCount() != 0 {
		t.Fatalf("warn mode must not drop events, dropped=%d", g.DroppedCount())
	}

	// In warn mode the timeline follows the newest observation: subsequent
	// strictly ordered events must pass.
	a, _ = g.Check(2, base.Add(-time.Hour+time.Second))
	if a != nil {
		t.Fatalf("ordered event after warned rewind rejected: %v", a)
	}
}

func TestTimelineGuardAbort(t *testing.T) {
	g := NewTimelineGuard(ModeAbort)
	g.Check(10, base)

	a, abort := g.Check(9, base.Add(-time.Second))
	if a == nil || !abort {
		t.Fatalf("abort mode: expected anomaly with abort flag, got %v abort=%v", a, abort)
	}
}

func TestTimelineGuardRecordRegression(t *testing.T) {
	g := NewTimelineGuard(ModeFailClosed)
	g.Check(10, base)

	// Timestamp stays equal (legal per se) but the record id regresses.
	a, _ := g.Check(9, base)
	if a == nil || a.Kind != ErrEventRecordRegression {
		t.Fatalf("expected ErrEventRecordRegression, got %v", a)
	}
}

func TestTimelineGuardTimeRegression(t *testing.T) {
	g := NewTimelineGuard(ModeFailClosed)
	g.Check(10, base)

	// Record id advances but the timestamp moves into the past.
	a, _ := g.Check(11, base.Add(-time.Second))
	if a == nil || a.Kind != ErrTimeRegression {
		t.Fatalf("expected ErrTimeRegression, got %v", a)
	}
	if g.DroppedCount() != 1 {
		t.Fatalf("expected dropped event, dropped=%d", g.DroppedCount())
	}
}

func TestTimelineGuardDuplicateRecord(t *testing.T) {
	g := NewTimelineGuard(ModeFailClosed)
	g.Check(10, base)

	// Same record id, different timestamp: cannot be the same event.
	a, _ := g.Check(10, base.Add(time.Second))
	if a == nil || a.Kind != ErrDuplicateRecord {
		t.Fatalf("expected ErrDuplicateRecord, got %v", a)
	}

	// Same record id, same timestamp: exact re-read of the same event, legal.
	a, abort := g.Check(10, base)
	if a != nil || abort {
		t.Fatalf("identical re-read must be legal, got %v abort=%v", a, abort)
	}
}

func TestTimelineGuardZeroIdentityPassesThrough(t *testing.T) {
	g := NewTimelineGuard(ModeAbort)

	// Missing timestamp / missing record id cannot be judged: pass through.
	if a, abort := g.Check(0, base); a != nil || abort {
		t.Fatalf("zero record id should pass through, got %v", a)
	}
	if a, abort := g.Check(1, time.Time{}); a != nil || abort {
		t.Fatalf("zero timestamp should pass through, got %v", a)
	}
}

func TestTimelineGuardReset(t *testing.T) {
	g := NewTimelineGuard(ModeAbort)
	g.Check(10, base)
	g.Reset()

	// After reset, a low record id must initialize a brand new timeline instead
	// of being reported as a rewind.
	if a, _ := g.Check(1, base.Add(-time.Hour)); a != nil {
		t.Fatalf("post-reset stream should start fresh, got %v", a)
	}
}

func TestTimelineGuardCheckEvent(t *testing.T) {
	g := NewTimelineGuard(ModeFailClosed)
	e1 := mkEvent(1, base)
	e2 := mkEvent(2, base.Add(time.Second))

	if a, _ := g.CheckEvent(e1); a != nil {
		t.Fatalf("first event rejected: %v", a)
	}
	if a, _ := g.CheckEvent(e2); a != nil {
		t.Fatalf("ordered event rejected: %v", a)
	}

	// Build a reopen-style event directly through GoEvtxMap paths.
	bad := mkEvent(1, base.Add(-time.Hour))
	a, _ := g.CheckEvent(bad)
	if a == nil || a.Kind != ErrTimelineRewind {
		t.Fatalf("CheckEvent: expected rewind anomaly, got %v", a)
	}
}

// TestFileTimelineGuardWiring verifies the File level API used by the
// MonitorEvents publishing loop: enabling the guard, retrieving it and checking
// that events flow through it with the configured policy. It does not need a
// real EVTX file since the guard itself is the component enforcing ordering.
func TestFileTimelineGuardWiring(t *testing.T) {
	ef := &File{}

	if ef.TimelineGuard() != nil {
		t.Fatal("new File must not carry a timeline guard by default")
	}

	g := ef.EnableTimelineGuard(ModeFailClosed)
	if ef.TimelineGuard() != g {
		t.Fatal("TimelineGuard getter must return the guard configured on the File")
	}
	if g.Mode() != ModeFailClosed {
		t.Fatalf("unexpected mode: %d", g.Mode())
	}

	// Simulate the exact sequence MonitorEvents runs for every published event.
	healthy := []*GoEvtxMap{
		mkEvent(1, base),
		mkEvent(2, base.Add(time.Second)),
		mkEvent(3, base.Add(time.Second)), // same timestamp as previous: legal
	}
	for _, e := range healthy {
		if a, abort := g.CheckEvent(e); a != nil || abort {
			t.Fatalf("healthy event must pass, got anomaly=%v abort=%v", a, abort)
		}
	}

	// Reopen replay: must be blocked in fail-closed and never abort the loop.
	replayed := mkEvent(1, base.Add(-time.Hour))
	a, abort := g.CheckEvent(replayed)
	if a == nil || a.Kind != ErrTimelineRewind || abort {
		t.Fatalf("replayed event must trigger a non-aborting rewind, got %v abort=%v", a, abort)
	}
	if g.DroppedCount() != 1 {
		t.Fatalf("expected 1 dropped event, got %d", g.DroppedCount())
	}

	// The stream recovers as soon as ordered events come back.
	recovered := mkEvent(4, base.Add(2*time.Second))
	if a, _ := g.CheckEvent(recovered); a != nil {
		t.Fatalf("recovered stream rejected: %v", a)
	}
}

// TestFileTimelineGuardDisabledByDefault locks in the historical behavior: no
// guard means no ordering enforcement at all.
func TestFileTimelineGuardDisabledByDefault(t *testing.T) {
	ef := &File{}
	g := ef.TimelineGuard()
	if g != nil {
		t.Fatalf("expected nil guard, got %v", g)
	}
}

// seqStep describes one event in a published sequence and the decision the
// guard is expected to take.
type seqStep struct {
	recordID int64
	offset   time.Duration // offset from base
	wantDrop bool          // true when fail-closed must reject the event
	wantKind error         // expected anomaly kind, nil for in-order events
}

func TestTimelineGuardReopenSequenceFailClosed(t *testing.T) {
	// Full reproduction of issue UID 39239: a healthy stream is consumed, then
	// the file is reopened and the consumer keeps publishing events in disk
	// order, replaying events with regressing timestamps and record ids, until
	// it catches up with the previous high watermark.
	steps := []seqStep{
		{1, 0, false, nil},
		{2, time.Second, false, nil},
		{3, 2 * time.Second, false, nil},
		// reopen: disk-order replay starts from the beginning of the file.
		// The first replayed event makes both identities go backwards at once
		// (timeline rewind). In fail-closed mode the anchor does not move, so
		// the following replayed records are seen as record id regressions /
		// conflicting duplicates: every one of them is rejected as well.
		{1, -time.Hour, true, ErrTimelineRewind},
		{2, -time.Hour + time.Second, true, ErrTimelineRewind},
		{3, -time.Hour + 2*time.Second, true, ErrDuplicateRecord},
		// new healthy event appended after the reopen
		{4, 3 * time.Second, false, nil},
		{5, 3 * time.Second, false, nil}, // equal timestamp, legal
	}

	g := NewTimelineGuard(ModeFailClosed)
	delivered := 0
	for i, s := range steps {
		a, abort := g.Check(s.recordID, base.Add(s.offset))
		if abort {
			t.Fatalf("step %d: fail-closed must never abort", i)
		}
		switch {
		case s.wantKind == nil && a != nil:
			t.Fatalf("step %d: expected in-order event, got anomaly %v", i, a)
		case s.wantKind != nil && (a == nil || a.Kind != s.wantKind):
			t.Fatalf("step %d: expected %v, got %v", i, s.wantKind, a)
		}
		if !s.wantDrop {
			delivered++
		}
	}

	// 3 replayed events dropped, 5 legitimate events delivered.
	if delivered != 5 {
		t.Fatalf("expected 5 delivered events, got %d", delivered)
	}
	if g.DroppedCount() != 3 {
		t.Fatalf("expected 3 dropped events, got %d", g.DroppedCount())
	}
	if g.RewindCount() != 2 {
		t.Fatalf("expected 2 detected rewinds (the third replayed record is a "+
			"duplicate id), got %d", g.RewindCount())
	}
}

func TestTimelineGuardWarnKeepsFullSequence(t *testing.T) {
	g := NewTimelineGuard(ModeWarn)
	events := []seqStep{
		{1, 0, false, nil},
		{2, time.Second, false, nil},
		{1, -time.Hour, false, ErrTimelineRewind},
		{2, -time.Hour + time.Second, false, nil},
	}
	anomalies := 0
	for i, s := range events {
		a, abort := g.Check(s.recordID, base.Add(s.offset))
		if abort {
			t.Fatalf("step %d: warn mode never aborts", i)
		}
		if s.wantKind != nil {
			if a == nil || a.Kind != s.wantKind {
				t.Fatalf("step %d: expected %v, got %v", i, s.wantKind, a)
			}
			anomalies++
			continue
		}
		if a != nil {
			t.Fatalf("step %d: unexpected anomaly %v", i, a)
		}
	}
	if anomalies != 1 || g.DroppedCount() != 0 {
		t.Fatalf("warn mode: expected 1 anomaly and 0 drops, got anomalies=%d drops=%d",
			anomalies, g.DroppedCount())
	}
}
