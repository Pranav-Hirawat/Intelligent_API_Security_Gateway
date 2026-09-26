import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { MODE_OPTIONS, effectiveModeText, modeCopy } from "../lib/adaptive-mode.mjs";
import { normalizeStoredAdaptive } from "../lib/adaptive-config.mjs";

test("each enforcement mode states the lifecycle it changes", () => {
  assert.equal(MODE_OPTIONS.length, 3);
  assert.match(modeCopy("monitor").behaviour, /Never write an enforcing gateway policy/);
  assert.match(modeCopy("manual").behaviour, /approve, edit, or reject/);
  assert.match(modeCopy("automatic").behaviour, /guardrail-compliant throttle or temporary-block/);
});

test("the adaptive page keeps enforcement choice concise and defers inactive activity", async () => {
  const page = await readFile(new URL("../app/(console)/adaptive/page.jsx", import.meta.url), "utf8");
  assert.match(page, /Learning always stays on; this only controls policy creation\./);
  assert.match(page, /Choose a mode/);
  assert.match(page, /Automatic action cap/);
  assert.match(page, /No adaptive activity yet/);
  assert.match(page, /Settings saved/);
  assert.doesNotMatch(page, /Emergency override/);
  assert.doesNotMatch(page, /Active policies/);
  assert.match(page, /Advanced settings/);
  assert.equal(effectiveModeText("automatic"), "Current effective mode: Automatic bounded enforcement");
});

test("a retired ML risk weight cannot be resubmitted from a stored configuration", () => {
  const stored = {
    risk: { deterministic_weight: 0.5, behavioural_weight: 0.2, campaign_weight: 0.3, ml_weight: 0 },
  };

  assert.deepEqual(normalizeStoredAdaptive(stored), {
    risk: { deterministic_weight: 0.5, behavioural_weight: 0.2, campaign_weight: 0.3 },
  });
  assert.equal(stored.risk.ml_weight, 0);
});
