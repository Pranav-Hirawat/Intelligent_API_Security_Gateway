package policy

import "testing"

type fake map[string]Decision

func (f fake) Lookup(ip string) (Decision, bool) {
	d, ok := f[ip]
	return d, ok
}

func TestChainReturnsTheFirstSourceThatHasAnOpinion(t *testing.T) {
	agent := fake{"203.0.113.1": {Action: ActionThrottle}}
	reflex := fake{"203.0.113.2": {Action: ActionTempBlock}}

	chain := Chain{agent, reflex}

	if d, ok := chain.Lookup("203.0.113.1"); !ok || d.Action != ActionThrottle {
		t.Errorf("agent decision = %+v %v, want throttle", d, ok)
	}
	if d, ok := chain.Lookup("203.0.113.2"); !ok || d.Action != ActionTempBlock {
		t.Errorf("reflex decision = %+v %v, want temp_block", d, ok)
	}
	if _, ok := chain.Lookup("203.0.113.3"); ok {
		t.Error("an address neither source knows about was given a decision")
	}
}

// The reflex hides every request after the one that armed it, so the engine
// decides on less than the reflex saw. Its milder answer must not lift the
// block: that is how a traversal attacker got back in a cycle after the probe.
func TestAMilderEngineDecisionCannotLiftAReflexBlock(t *testing.T) {
	agent := fake{"203.0.113.9": {Action: ActionThrottle, Source: "adaptive"}}
	reflex := fake{"203.0.113.9": {Action: ActionTempBlock, Source: "gateway_reflex"}}

	d, ok := Chain{agent, reflex}.Lookup("203.0.113.9")
	if !ok || d.Action != ActionTempBlock || d.Source != "gateway_reflex" {
		t.Errorf("got %+v, want the reflex block to stand", d)
	}
}

func TestTheMoreSevereActionWinsAndTheEngineKeepsTies(t *testing.T) {
	for name, tc := range map[string]struct {
		agent, reflex Decision
		want          string
	}{
		"engine escalates past the reflex": {Decision{Action: ActionEscalate}, Decision{Action: ActionTempBlock}, "engine"},
		"equal blocks keep the engine's":   {Decision{Action: ActionTemporaryBlock}, Decision{Action: ActionTempBlock}, "engine"},
		"an unknown label never outranks":  {Decision{Action: "quarantine"}, Decision{Action: ActionTempBlock}, "reflex"},
	} {
		tc.agent.Reason, tc.reflex.Reason = "engine", "reflex"
		d, _ := Chain{fake{"203.0.113.9": tc.agent}, fake{"203.0.113.9": tc.reflex}}.Lookup("203.0.113.9")
		if d.Reason != tc.want {
			t.Errorf("%s: got the %s decision %+v", name, d.Reason, d)
		}
	}
}

// A human override is how an address the gateway blocked by itself is released,
// so a person's decision wins even when it is milder.
func TestAPersonsInstructionOutranksTheReflex(t *testing.T) {
	for _, human := range []Decision{
		{Action: ActionAllow, Source: "human"},
		{Action: ActionThrottle, Mode: "manual_override"},
	} {
		d, ok := Chain{fake{"203.0.113.9": human}, fake{"203.0.113.9": {Action: ActionTempBlock}}}.Lookup("203.0.113.9")
		if !ok || d.Action != human.Action {
			t.Errorf("human %+v: got %+v", human, d)
		}
	}
}

func TestChainSkipsMissingSources(t *testing.T) {
	// Policy enforcement off, reflex on, is a supported combination and must
	// not depend on the order the sources happen to be appended in.
	reflex := fake{"203.0.113.4": {Action: ActionTempBlock}}

	if _, ok := (Chain{nil, reflex}).Lookup("203.0.113.4"); !ok {
		t.Error("a nil source hid the one that had an answer")
	}
	if _, ok := (Chain{}).Lookup("203.0.113.4"); ok {
		t.Error("an empty chain returned a decision")
	}
}
