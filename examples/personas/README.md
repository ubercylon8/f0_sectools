# One finding, five altitudes

The same two findings — a Defender brute-force alert on `web-01` and a related
Entra risky sign-in — rendered by every persona renderer in `core/renderers/`.
The structured [finding](../../docs/explanation/findings-schema.md) is always
the data contract; these views are presentation, rendered **deterministically
and model-free** (no LLM in the loop).

Every output below is produced by real code — reproduce it with:

```bash
uv run python examples/personas/render_example.py
```

## `soc_analyst` — tactical: what happened, next triage step

```markdown
2 findings (1 high, 1 medium)

**[HIGH] Brute-force authentication against host web-01**
Target: host: web-01.corp.local (web-01)
What happened:
- failed_logins: 142 in 5m
- source_ip: 203.0.113.44
- account_targeted: svc-backup
Next step: Isolate host and reset affected credentials (gated action: defender.isolate_host)

**[MEDIUM] Risky sign-in for user svc-backup (unfamiliar location)**
Target: user: svc-backup@corp.local (svc-backup)
What happened:
- risk_state: atRisk
- detection: unfamiliarFeatures
Next step: Review sign-in and consider credential reset
```

## `security_engineer` — a remediation checklist grouped by platform

```markdown
## Remediation checklist
### defender
- [ ] Isolate host and reset affected credentials (defender/alert)
### entra
- [ ] Review sign-in and consider credential reset (entra/risk)
```

## `ciso` — aggregate rollup, business-framed, no raw evidence

```markdown
## Security posture rollup
Total findings: 2
By severity: 1 high, 1 medium
By source: 1 defender, 1 entra
Top findings:
- [HIGH] Brute-force authentication against host web-01 — host: web-01.corp.local (web-01)
- [MEDIUM] Risky sign-in for user svc-backup (unfamiliar location) — user: svc-backup@corp.local (svc-backup)
Risk posture: 1 critical/high finding(s) require attention.
```

## `threat_hunter` — timeline, pivots, IOCs, ATT&CK

```markdown
## Timeline
2026-06-28T10:00:00Z — [HIGH] Brute-force authentication against host web-01
Pivot: host: web-01.corp.local (web-01)
IOCs:
- failed_logins: 142 in 5m
- source_ip: 203.0.113.44
- account_targeted: svc-backup
ATT&CK: mitre:T1110
2026-06-28T10:02:00Z — [MEDIUM] Risky sign-in for user svc-backup (unfamiliar location)
Pivot: user: svc-backup@corp.local (svc-backup)
IOCs:
- risk_state: atRisk
- detection: unfamiliarFeatures
ATT&CK: mitre:T1078
```

## `detection_engineer` — grouped by technique, coverage-framed

```markdown
## Detection coverage by technique
### T1078
- Risky sign-in for user svc-backup (unfamiliar location) (MEDIUM)
### T1110
- Brute-force authentication against host web-01 (HIGH)
```

Notice what changed and what didn't: the *facts* are identical in all five;
the selection, ordering, and framing differ. That is the design — tools always
emit the structured finding, and the persona view is a lens, never a different
data contract. The **agent personas** (which shape behaviour, not text) are a
separate layer — see
[using skills & personas](../../docs/user-guide/using-skills-and-personas.md).
