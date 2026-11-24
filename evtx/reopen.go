package evtx

// CommittedState is the durable EVTX file-header state used to schedule a new
// traversal. It is an alias because FileHeader is already the public snapshot
// of the committed log geometry.
type CommittedState = FileHeader

// CommittedState returns the header of the current durable log generation.
// Callers that close and reopen a consumer should use this snapshot rather than
// retaining offsets or parser caches from the previous generation.
func (ef *File) CommittedState() CommittedState {
	return ef.HeaderSnapshot()
}

// eventReplayFilter suppresses duplicate publications within one public event
// stream traversal.
//
// The filter is intentionally local to a single Events/FastEvents/... call.
// Closing and reopening a log starts a new traversal with an empty filter, so a
// legitimate complete replay of a stable file is emitted again instead of being
// suppressed by a consumer-wide cursor.
type eventReplayFilter map[uint64]struct{}

func newEventReplayFilter() eventReplayFilter {
	return make(eventReplayFilter)
}

// admit reports whether event can be published. Events without a readable,
// non-zero EventRecordID cannot be bound to committed log identity and are
// passed through to preserve historical parsing behavior.
func (f eventReplayFilter) admit(event *GoEvtxMap) bool {
	if f == nil {
		return true
	}
	if event == nil {
		// Preserve the historical channel contract; callers such as
		// evtxdump already guard nil events.
		return true
	}

	recordID, err := event.GetUint(&EventRecordIDPath)
	if err != nil || recordID == 0 {
		return true
	}

	if _, seen := f[recordID]; seen {
		return false
	}
	f[recordID] = struct{}{}
	return true
}
