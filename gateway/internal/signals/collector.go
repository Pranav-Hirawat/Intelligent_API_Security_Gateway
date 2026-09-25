package signals

// Collector gathers Evidence from every registered detector for one IP.
// Telemetry asks it for a snapshot instead of talking to detectors
// individually.
type Collector struct {
	detectors []Detector
}

func NewCollector(detectors ...Detector) *Collector {
	return &Collector{detectors: detectors}
}

// collect gathers evidence for an IP. With a request id, detectors that
// describe a single request are asked only for that request's evidence;
// windowed detectors always report their rolling state, which stays true
// whether or not this particular request reached them.
func (c *Collector) collect(ip, requestID string) []Evidence {
	if c == nil {
		return nil
	}
	out := make([]Evidence, 0, len(c.detectors))
	for _, d := range c.detectors {
		if d == nil {
			continue
		}
		if requestID != "" {
			if scoped, ok := d.(RequestScoped); ok {
				out = append(out, scoped.MetricsFor(ip, requestID))
				continue
			}
		}
		out = append(out, d.Metrics(ip))
	}
	return out
}

// Snapshot is one collection plus derived totals for telemetry / scoring.
type Snapshot struct {
	Evidence   []Evidence
	TotalScore int
	Fired      []string
}

// SnapshotFor is a snapshot for a single request, so what telemetry records is
// what that request actually carried rather than what the address did last.
func (c *Collector) SnapshotFor(ip, requestID string) Snapshot {
	return summarize(c.collect(ip, requestID))
}

func summarize(evs []Evidence) Snapshot {
	snap := Snapshot{Evidence: evs}
	for _, ev := range evs {
		snap.TotalScore += ev.Score
		if ev.ThresholdCross {
			// One canonical id per detector, even when AttackType carries a
			// more specific label (enumeration_path_traversal.go sets it to
			// "path_traversal"/"enumeration"/the compound). That detail
			// still travels on this same Evidence in the Signals array
			// (evidence.go's AttackType field) for anything that wants it --
			// duplicating it into Fired only produced a second, detail-less
			// event downstream for one detector.
			snap.Fired = append(snap.Fired, ev.Signal)
		}
	}
	// Individual signals contribute on a 0-100 scale, but several can fire on
	// one request. Telemetry exposes one risk score, so retain the combined
	// evidence while keeping that public value on its documented 0-100 scale.
	snap.TotalScore = clampScore(snap.TotalScore)
	return snap
}
