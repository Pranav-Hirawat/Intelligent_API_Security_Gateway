package telemetry

import (
	"testing"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
)

// Every action the enforcer refuses a request with must name why, whichever
// spelling the policy used. Adaptive policies write "temporary_block"; an
// event missing its reason reads as a refusal nobody can explain.
func TestEveryRefusingPolicyActionNamesAGatewayReason(t *testing.T) {
	for _, action := range []string{policy.ActionBlock, policy.ActionTempBlock, policy.ActionTemporaryBlock, policy.ActionEscalate} {
		if got := gatewayReasonFor(action); got != ReasonPolicyBlock {
			t.Errorf("gatewayReasonFor(%q) = %q, want %q", action, got, ReasonPolicyBlock)
		}
	}
	if got := gatewayReasonFor(policy.OutcomeRateLimited); got != ReasonRateLimited {
		t.Errorf("rate limited: %q", got)
	}
	for _, served := range []string{policy.ActionAllow, policy.ActionMonitor, policy.ActionThrottle, ""} {
		if got := gatewayReasonFor(served); got != "" {
			t.Errorf("gatewayReasonFor(%q) = %q, but the backend answered", served, got)
		}
	}
}

// The ownership guard asks the backend and then replaces its answer. The client
// got the gateway's answer, so that is the origin -- even though a backend
// status was measured.
func TestAGatewayReasonMakesTheGatewayTheOrigin(t *testing.T) {
	answered := &Upstream{Attempted: true, HaveStatus: true, Status: 200}
	if got := answered.Origin(); got != OriginBackend {
		t.Errorf("backend answer: origin %q", got)
	}
	answered.GatewayReason = ReasonOwnershipRefused
	if got := answered.Origin(); got != OriginGateway {
		t.Errorf("replaced answer: origin %q, want %q", got, OriginGateway)
	}
}
