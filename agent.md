# Agent Working Agreement

> Read this file first. Every session. No exceptions.
> Then read progress.md. Then begin work.

---

## Session Start (do this in order)

1. Read `progress.md` → find **Current phase**, **Next task**, **Notes for Next Session**
2. Check Blockers table — resolve before proceeding
3. Check Deviations table — understand what changed from plan
4. State: *"Resuming from [task ID]. Next action is [Y]."*
5. If a `docs/feature-NN-plan.md` exists for the current phase, read it before starting
6. Begin work on **one task at a time** — no skipping, no batching without a checkpoint

If `progress.md` is missing → create it from the template in `docs/card-tokenisation-plan.md §14` first.

---

## Plan File Locations

```
docs/card-tokenisation-plan.md   ← baseline (architecture, standards, load test specs)
docs/feature-NN-plan.md          ← created when a new feature is agreed, not speculatively
progress.md                      ← session state, task tracking, deviations, blockers
docs/agent-code-standards.md     ← clean code + anti-slop rules (read when writing code)
docs/agent-test-standards.md     ← testing rules + load test gate (read when writing tests)
```

---

## Definition of Done

A task is `[x]` only when **all** of these are true:

- [ ] Compiles with zero warnings
- [ ] Every public class and method has Javadoc (`@param`, `@return`, `@throws`)
- [ ] Unit tests written and passing, coverage ≥ 90% for service/crypto classes
- [ ] Integration test written and passing (where applicable)
- [ ] No PAN or key material appears in any log output
- [ ] No `TODO` or `FIXME` left in code
- [ ] All rules in `docs/agent-code-standards.md` satisfied
- [ ] `progress.md` updated — task marked `[x]`, `Next task` updated

---

## Progress Tracking

- Update `progress.md` **after each task** — not end of session
- Mark `[x]` only when Definition of Done is fully met — no partial credit
- Record any deviation from the plan in the Deviations table **before** continuing
- Record blockers immediately — never silently skip a task
- Update **Notes for Next Session** before ending every session

---

## Task Execution (every task, in order)

```
1. READ   — read the task in progress.md and the matching section in the plan
2. PLAN   — state what you will create and what tests you will write
3. TEST   — write the test first for service/business logic; confirm it fails
4. CODE   — implement; write Javadoc before the method body
5. VERIFY — run tests; check coverage; re-read against agent-code-standards.md
6. CHECKPOINT — update progress.md before moving on
```

---

## Absolute Rules (never violate)

| # | Never do this |
|---|---|
| 1 | Write a public method without Javadoc |
| 2 | Mark a task `[x]` without meeting every Definition of Done item |
| 3 | Log PAN, key bytes, or secrets at any level |
| 4 | Catch an exception and return `null` |
| 5 | Use `@Autowired` on a field — constructor injection only |
| 6 | Write a test with no meaningful assertion (`assertNotNull` alone is not enough) |
| 7 | Use generic variable names: `result`, `data`, `temp`, `obj`, `val` |
| 8 | Leave a `TODO` or `FIXME` — do it now or add it to `progress.md` |
| 9 | Write code for requirements not in the plan (no speculation) |
| 10 | Proceed to the next task without updating `progress.md` |
| 11 | Start a session without reading `progress.md` first |
| 12 | Mark a load test `[x]` without running it against the full stack (no mocks) |

---

## When to Read the Reference Files

| Situation | Read this |
|---|---|
| Writing any production class | `docs/agent-code-standards.md` |
| Writing any test | `docs/agent-test-standards.md` |
| Load test is the current task | `docs/agent-test-standards.md §Load Tests` |
| Implementing crypto or key ring | `docs/card-tokenisation-plan.md §5` and `§8` |
| Starting a new phase | `docs/card-tokenisation-plan.md` — the relevant phase section |
| Creating a feature plan | Follow the feature plan structure in `docs/card-tokenisation-plan.md §14` |

---

*Version 2.0 — lean core. Full standards in `docs/agent-code-standards.md` and `docs/agent-test-standards.md`.*
