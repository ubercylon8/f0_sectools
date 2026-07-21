---
name: investigate-audit-activity
description: Search the M365 unified audit log for user activity
version: 1.0.0
metadata:
  hermes:
    tags: [security, purview, audit, investigation, hunter]
    category: security
---

# Investigate Unified-Audit Activity (Microsoft Purview)

## When to Use

The user asks **who did what** in Microsoft 365: "who deleted files
yesterday", "what did jsmith do today", "any mass downloads from SharePoint".

## Procedure

Base tool names: `search_audit_log`, `get_audit_results`.

1. Call `search_audit_log` with flat filters: `activity` (an operation name
   like "FileDeleted", "FileDownloaded", "MailItemsAccessed") and/or `user`
   (a UPN), plus a bounded `hours_back` (start small: 4–24h).
2. **The search is asynchronous.** If the result is a posture finding saying
   the search is still running, it carries an `audit_query_id` — tell the
   user the search is running, wait a minute or two (audit queries can take
   several minutes on large tenants), then call `get_audit_results` with that
   exact id. Do NOT resubmit a new search for the same question.
3. When records arrive, relay: operation, user, service, time, object —
   grouped by user or operation if there are many.
4. Refine once or twice (narrower window, specific user) rather than pulling
   large result sets.

## Pitfalls

- Resubmitting instead of using `get_audit_results` creates duplicate
  server-side queries and doubles the wait — always reuse the
  `audit_query_id`.
- An empty result for a narrow window is normal; widen `hours_back` once
  before concluding "no activity".
- `activity` must be an exact operation name — if unsure, run once with no
  `activity` filter and read the operation names that come back.

## Verification

Every claimed action maps to a returned audit record finding; the
`audit_query_id` in the summary ties results to the submitted search.
