# Sample findings — one per server

One representative finding from each of the eight MCP servers, showing the
**same normalized shape** regardless of platform — the point of the
[findings schema](../../docs/explanation/findings-schema.md). All values are
fictional (example.com-style hosts and GUIDs); shapes mirror what the
live-validated servers emit.

Every file is **schema-validated in CI** (`scripts/tests/test_examples_valid.py`
parses each one with the real pydantic `Finding` model), so these examples
cannot drift from the contract.

| File | Shows |
|---|---|
| [`defender.json`](defender.json) | an `incident` with a `gated_action` bridge (`isolate_host`) |
| [`entra.json`](entra.json) | a `risk` finding on a user entity (Identity Protection) |
| [`limacharlie.json`](limacharlie.json) | an EDR `alert` with ATT&CK reference and truncated-by-design evidence |
| [`projectachilles.json`](projectachilles.json) | a validation `risk` — a weak technique with test counts |
| [`projectachilles-actions.json`](projectachilles-actions.json) | an **intent** finding (`finding_type: "action"`) — what a gated write returns *before* any confirmation |
| [`intune.json`](intune.json) | a `misconfig` on a device entity (stale device) |
| [`tenable.json`](tenable.json) | a critical `misconfig` (the [offline demo](../../docs/demo.md)'s Log4Shell output) |
| [`purview.json`](purview.json) | a data-risk `alert` (DLP) |

Reading order for the schema's ideas: `tenable.json` (plain read),
`defender.json` (read that *names* a gated action without invoking it), then
`projectachilles-actions.json` (the gated-write intent vocabulary — see the
[security model](../../docs/explanation/security-model.md#gated-write-actions)).
