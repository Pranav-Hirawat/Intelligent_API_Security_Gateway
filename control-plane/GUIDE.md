# Control Plane — file by file

This page originally walked through the control plane as it stood on the
`pranav/agentic-evidence-pipeline` branch, before gateway enforcement,
`iasg/adaptive/` and `iasg/policy/simulation.py`
path existed. That snapshot is no longer a safe way to learn the current
system — enough has changed underneath it (test count, module list, which
code path is actually live) that patching it line by line would mean
rewriting nearly the whole page, duplicating material two other documents
already keep current:

- **[Every algorithm the agent runs](ALGORITHMS.md)** is the up-to-date
  "file by file, in the order it makes sense to read it" guide this page used
  to be.
- **[The presentation walkthrough](PRESENTATION.md)** covers the same ground
  at demo pace, with the live talking points.
- **[Adaptive Policy and Analyst Control](../gateway/docs/adaptive-policy.md)**
  documents the engine that actually decides and enforces today —
  `iasg/adaptive/`. The fixed action ladder this page once described has been
  removed; `ALGORITHMS.md` lists what `iasg/policy/` still does.

If you're looking for the specific history of how evidence → campaign →
policy was first built, before enforcement existed to act on it, that's still
in git history on the `pranav/agentic-evidence-pipeline` branch and the PRs
that followed it — this page just shouldn't be read as a description of the
code as it stands today.
