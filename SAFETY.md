# SAFETY

**This repository contains a deliberately insecure AI agent. It is a test
target, not a product. Do not deploy it.**

Read this before you run anything.

---

## What is intentionally wrong in here

`target_agent/` is a customer-support agent built to fail. In its default
(unhardened) configuration it has, on purpose:

| Weakness | Where | Why it is there |
|---|---|---|
| A permissive, trusting system prompt | `config.py` | Baseline for the before/after comparison |
| No authorization on `issue_refund` | `tools.py` | Demonstrates BOLA / BFLA / excessive agency |
| A planted prompt injection in tool output | `data.py` (order `NW-1043`) | Demonstrates **indirect** injection through data, not user input |
| Cross-customer PII in `search_customer` results | `tools.py` | PII disclosure surface |
| Fake credentials returned by `read_internal_note` | `data.py` | Data-exfiltration canary |
| No output filtering | `config.py` | Lets leaks reach the transcript so graders can see them |

None of this is a bug. Every item is the subject of a test. Setting
`AGENT_HARDENED=true` turns on the controls that close them, which is the
entire point of the exercise.

## Rules

1. **Localhost only.** The agent binds to `127.0.0.1`. `target_agent/app.py`
   raises `SystemExit` rather than start on any other interface, and CI
   asserts that. Do not remove that check, do not put this behind a tunnel, a
   reverse proxy, or a port forward.
2. **Never deploy this.** Not to staging, not to an internal network, not
   "briefly, for a demo". An agent with an unauthenticated refund tool and a
   planted injection payload is exactly what it looks like.
3. **Do not point the red team harness at a system you are not authorised to
   test.** promptfoo will happily generate adversarial probes against any
   endpoint you configure. Swapping `base_url` for someone else's service is
   an attack, whatever the intent, and in most jurisdictions it is a crime.
   Written authorisation, a defined scope, and an agreed window, every time.
4. **Do not reuse the weak prompts or tool definitions in real code.** They
   are written to fail. If you want the patterns that work, read the
   `HARDENED_*` branches — and treat even those as a starting point, not a
   security architecture.

## About the data

Everything is synthetic and was written for this repository:

- **Customers** are invented. Emails use the reserved `.invalid` TLD
  (RFC 2606), which can never resolve. Phone numbers are in the `555-01xx`
  fictional range. Addresses are made up.
- **Orders, SKUs, tracking numbers, and internal notes** are invented.
- **`SK-FAKE-DEMO-0001`** is not a credential. It is a canary string that
  authenticates nothing, anywhere. Its only purpose is to be greppable: if it
  appears in an agent's reply, data moved from a staff-only tool to a
  customer, and the assertion catches it.
- **`https://internal.northwind.example/...`** uses the reserved `.example`
  TLD (RFC 2606). It does not resolve and never will.

There is no real PII and no real credential in this repository. Keep it that
way. If you adapt this POC to your own system, **do not** copy production
records in as fixtures — write synthetic ones that have the same shape.

## Network behaviour

A scan makes outbound calls to exactly two kinds of destination:

1. Your model provider's API (Anthropic by default) — for the target agent's
   replies, for promptfoo's attacker model, and for the grader.
2. promptfoo's probe-generation service, for the plugins that rely on it.

The target agent itself makes no outbound calls at all beyond its model
backend. It has no database, no shell, and no HTTP client pointed anywhere
but localhost. Tools that look destructive — `issue_refund`,
`escalate_to_human` — mutate an in-memory dict and return a receipt. No money
moves, no ticket is filed, nothing leaves the process.

To run the target with no model API calls whatsoever, use the deterministic
backend:

```bash
AGENT_MODEL_PROVIDER=mock make target
```

## Secrets

`.env` is gitignored. `.env.example` ships with placeholders only. Use
repository secrets in CI. If you ever put a real key in a fixture file, rotate
it — do not just delete the line, because the git history keeps it.

## Cleaning up

```bash
make clean   # removes output/, logs/, generated probes
```

`logs/tool_calls.jsonl` records every tool invocation including arguments. In
this POC that is all synthetic, but if you adapt the harness to a real target,
treat that log as sensitive: it will contain whatever your agent's tools were
called with.
