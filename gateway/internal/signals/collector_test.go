package signals

import (
	"reflect"
	"testing"
)

type fixedScoreDetector struct {
	name  string
	score int
}

func (d fixedScoreDetector) Metrics(string) Evidence {
	return Evidence{Signal: d.name, Score: d.score}
}

func TestCollectorTotalScoreIsAlwaysBounded(t *testing.T) {
	tests := []struct {
		name   string
		scores []int
		want   int
	}{
		{name: "combined signals cap at 100", scores: []int{80, 50}, want: 100},
		{name: "negative input cannot make risk negative", scores: []int{-25}, want: 0},
		{name: "ordinary combined score is preserved", scores: []int{20, 30}, want: 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detectors := make([]Detector, 0, len(tt.scores))
			for i, score := range tt.scores {
				detectors = append(detectors, fixedScoreDetector{name: string(rune('a' + i)), score: score})
			}

			if got := NewCollector(detectors...).SnapshotFor("203.0.113.5", "").TotalScore; got != tt.want {
				t.Fatalf("TotalScore() = %d, want %d", got, tt.want)
			}
		})
	}
}

// A fired signal always contributes its canonical Signal id, never a more
// specific AttackType -- enumeration_path_traversal.go is the one detector
// where those differ, and used to make summarize() emit both, producing a
// second, detail-less event downstream for one detector's single match.
func TestSummarizeFiresCanonicalSignalNotAttackType(t *testing.T) {
	ev := Evidence{
		Signal:         SignalTraversal,
		Score:          70,
		ThresholdCross: true,
		AttackType:     "path_traversal+enumeration",
	}

	got := summarize([]Evidence{ev}).Fired
	want := []string{SignalTraversal}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Fired = %v, want %v", got, want)
	}
}
