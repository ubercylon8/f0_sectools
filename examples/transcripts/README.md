# Annotated transcripts

Sessions showing f0_sectools driven end-to-end, with commentary on *why* each
step happened. Values are fictional; tool names, argument shapes, finding
shapes, refusal messages, and CLI output match the live-validated
implementation.

- **[defender-triage.md](defender-triage.md)** — a small local model triages
  two Defender incidents via the `triage-defender-incident` skill: flat-enum
  args, findings chained across tools, response actions named but correctly
  deferred. The read-only happy path.
- **[gated-run-test.md](gated-run-test.md)** — the full gated-write
  lifecycle: refusal with the flag off, intent-not-execution with the flag on,
  out-of-band watcher approval, execution consuming the single-use approval,
  and the audit line. The two-key hard stop, demonstrated.

Pair with the matching [workflows](../../docs/user-guide/workflows.md) to run
the same tasks against your own tenant.
