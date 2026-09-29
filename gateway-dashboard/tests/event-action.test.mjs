// The Events "Action" column. A request the gateway refused must never read as
// allowed, whichever part of the gateway refused it.
import assert from "node:assert/strict";
import test from "node:test";

import { actionLabel, eventAction } from "../app/ui/format.js";

test("a policy's action is shown as it was applied", () => {
  for (const decision of ["temporary_block", "temp_block", "throttle", "rate_limited", "escalate"]) {
    assert.equal(eventAction({ decision, status: 403 }), decision);
  }
  assert.equal(actionLabel("rate_limited"), "Rate limited");
});

test("a refusal the gateway made without a policy is not shown as allowed", () => {
  for (const [gatewayReason, status] of [
    ["ownership_refused", 404], ["authentication_required", 401], ["body_too_large", 413], ["body_unreadable", 400],
  ]) {
    const action = eventAction({ decision: "allow", status, responseOrigin: "gateway", gatewayReason });
    assert.equal(action, gatewayReason);
    assert.match(actionLabel(action), /^Refused: /);
  }
});

test("a request the backend answered is allowed, even when it answered with an error", () => {
  assert.equal(eventAction({ decision: "allow", status: 404, responseOrigin: "backend" }), "allow");
  assert.equal(eventAction({ status: 200 }), "allow");
  assert.equal(eventAction(), "allow");
});

test("a policy's own reason never replaces the action it names", () => {
  assert.equal(eventAction({ decision: "temporary_block", gatewayReason: "policy_block" }), "temporary_block");
  assert.equal(eventAction({ decision: "rate_limited", gatewayReason: "rate_limited" }), "rate_limited");
});
