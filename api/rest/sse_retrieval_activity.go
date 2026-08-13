package rest

import "fmt"

// emitContentlessRetrievalActivity is the ONLY sanctioned way for a memory
// retrieval path (recall, text search, hybrid search) to announce activity on
// the dashboard event stream.
//
// WHY THIS EXISTS AS A CHOKE POINT RATHER THAN THREE INLINE CALLS.
// Retrieval results are filtered by the CALLING agent's clearance and domain
// ACL. The dashboard stream they are announced on is a GLOBAL FAN-OUT with no
// subscriber identity: web/sse.go's Subscribe() takes no arguments, its client
// map value is struct{}{}, and Broadcast marshals one payload and pushes
// identical bytes to every connected client. There is therefore no place to
// enforce "who may see this" on that path, and no per-subscriber dimension a
// test could assert on. The only durable defence is to ensure nothing worth
// protecting is put in.
//
// These three sites previously published memory_id, content, domain,
// confidence and type for every result, plus the caller-derived domain in the
// event's Domain field. The stock dashboard rendered that content verbatim in
// its expandable Chain Activity rows, so one agent's authorized read set was
// republished to every connected dashboard.
//
// WHAT MAY CROSS THIS BOUNDARY: the event type, and a count. Nothing else.
// A count discloses only that a retrieval of some size happened, which the
// activity indicator exists to convey. Adding any per-result field, the
// caller's domain, or a free-form string built from result data reintroduces
// the disclosure — the accompanying wire-level tests fail if it does.
//
// Deliberately NOT solved here: making the broadcaster identity-aware. That is
// a larger change, and a per-call-site discipline is only as good as the next
// call site. Until the broadcaster carries subscriber identity, every new
// emitter is a fresh opportunity for this bug.
func emitContentlessRetrievalActivity(onEvent EventCallback, eventType string, resultCount int) {
	if onEvent == nil {
		return
	}
	// Positional contract of EventCallback is
	// (eventType, memoryID, domain, content, data). memoryID and domain are
	// held empty on purpose: both are authorization-scoped. content carries the
	// count only, and data is nil so no structured result material can ride
	// along.
	onEvent(eventType, "", "", fmt.Sprintf("%d memories", resultCount), nil)
}
