package telemetry

import "time"

// Arrival is what the gateway knows about a request before it runs.
//
// Windowing uses arrival time, not completion time. A request that arrives at
// 12:00:59 and finishes at 12:01:02 still belongs to the 12:00 window, and
// with completion records alone the extractor would never learn it existed --
// so a burst straddling a boundary reads as two smaller ones. Slow requests
// are exactly the ones an attack produces, so that error is not random.
//
// It also makes the in-flight ones visible at all. A request the gateway is
// still holding has no completion record yet, and a request the backend never
// answers never gets one.
//
// Deliberately a separate stream rather than a kind field on iasg:events: the
// console, the iasg:stats and iasg:attackers counters, and the decision engine's
// Evidence consumer all read that stream, and none of them should have to
// learn to skip half of it.
type Arrival struct {
	RequestID string    `json:"requestId"`
	ArrivalTS time.Time `json:"arrivalTs"`
	IP        string    `json:"ip"`
	Method    string    `json:"method"`

	// Uncleaned, for the same reason Event.Path is: ../ segments are the
	// behaviour, not noise.
	Path          string `json:"path"`
	RouteTemplate string `json:"routeTemplate"`

	// ContentLength is what the client declared, which is all that is known
	// before the body is read -- and it is -1 when the client declared
	// nothing. Event.RequestBodyBytes carries the measured figure.
	ContentLength int64 `json:"contentLength"`
}
