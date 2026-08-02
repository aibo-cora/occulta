# Occulta — Documentation Language Risk Review

**Date:** 2026-08-01
**Branch:** `release/v1.10.0`
**Scope:** All 45 Markdown docs under the repo (`Docs/`, `Occulta/Features/*/`, root-level `README.md`/`privacy-policy.md`/`support.md`) plus all 14 pages of the public GitHub wiki (`aibo-cora/occulta.wiki`). Not a security or correctness review — this audits *language*, specifically whether documentation could be read as evidence of intent to defeat a specific lawful government process (border search, compelled unlock, subpoena, forensic investigation), as opposed to describing generic coercion-resistance (abusive partner, kidnapper, thief, authoritarian non-judicial seizure).
**Why this exists:** Raised during a conversation about *Samuel Tunick* (first known U.S. prosecution built around a duress-password feature, charged under 18 U.S.C. §2232 for a GrapheneOS wipe triggered at a CBP border stop) and whether Occulta's own key-rotation/duress design carries analogous exposure under §2232 or the broader obstruction statute §1519. Conclusion from that discussion, not re-litigated here: the legal risk tracks *intent and effect*, not implementation mechanism, and the project's own design docs are discoverable — so the docs' wording is itself part of the risk surface, independent of what the code does. **This is not a legal opinion.** Severity below reflects how directly the wording ties the project to defeating a *named* government process, not an assessment of what a court would actually do with it.

---

## Status

**Tier 1 (fixed 2026-08-01):** the three most exposed passages — operational sequencing tied to a named checkpoint ("activate on airplane mode before landing, deactivate after clearing customs"), a verbatim community quote naming a "border agent," and a public wiki page naming "border crossings" — were rewritten to generic coercion/high-risk-inspection language and are shipped:
- [`Docs/Features/Master Feature & Expansion Analysis.md`](../../Features/Master%20Feature%20&%20Expansion%20Analysis.md), lines 65 and 67 (Offline Travel Mode section)
- `occulta.wiki/Secure-Mode.md`, line 3 (pushed to the public wiki, commit `228e1fe`)

**Tiers 2–4 below are open.** Documented here for a later pass — recommend routing through counsel before editing, same as the reasoning that produced the Tier 1 fixes.

---

## Tier 2 — Vocabulary pattern: "forensic examiner" as the standing adversary term

Not any single passage — a consistent word choice across the internal Secure Mode engineering docs. "Examiner" skews toward professional/government forensics; "coercer" (used elsewhere in the same docs) is the generic-threat term. No single instance below is alarming alone; the pattern, read as a whole, signals the primary threat model is a professional forensic investigation rather than personal coercion.

**Representative instances** (not exhaustive — `forensic-trace-avoidance.md` and `bugs.md` alone account for 40+):
- [`Occulta/Features/SecureMode/forensic-trace-avoidance.md:3`](../../../Occulta/Features/SecureMode/forensic-trace-avoidance.md) — the document's own scope statement: *"Documents every measure taken to prevent a forensic examiner from detecting Secure Mode activation, recovering sensitive contact data, or observing behavioural tells — even with physical device access and raw filesystem/database tools."*
- `Occulta/Features/SecureMode/bugs.md:225` — *"the forensic protection that prevents a duress-mode examiner from finding them at the SQLite layer"*
- `Occulta/Features/SecureMode/bugs.md:2287-2292` — *"A forensic examiner who captures a filesystem image at two points in time can infer..."*
- `Occulta/Features/SecureMode/plan.md:489` — *"A forensic examiner checking the Keychain will see a new SE key created and an old one deleted... The deletion IS the security mechanism — there is no way to hide it."*
- `Occulta/Features/SecureMode/LayerStore.md:214,235`, `scenarios.md`, `SecureMode+RotationContract.md:194` — same term, architecture-doc context.
- `Docs/Features/Message Persistence/FINDINGS.md:65,87,107`, `Docs/Features/Group Messaging/FINDINGS.md:88,96,210,212,236,327` — same pattern outside the Secure Mode subsystem.
- `Docs/Audit/SecurityReview2026-07-24/README.md:89` — inherited into the security-review doc itself.

**Note:** this vocabulary is largely *necessary* for the docs to do their job — you can't threat-model without naming the adversary precisely. A full pass would mean deciding whether to standardize on "coercer"/"adversary" throughout (matching the language already used for the PIN/duress-layer sections) rather than removing the concept.

---

## Tier 2b — Explicit self-admissions ("anti-forensic")

Two spots where the docs name their own risk in exactly the words a prosecutor would want to read back:

- [`Docs/Features/Message Persistence/FINDINGS.md:488`](../../Features/Message%20Persistence/FINDINGS.md) — on why a bundled on-device model was rejected: *"a prompt reading something like 'write a casual abandoned text message' sitting in the binary's strings section isn't ambiguous evidence the way a word list is — it's **a direct confession of anti-forensic intent**."*
- [`Docs/Features/Message Persistence/FINDINGS.md:504`](../../Features/Message%20Persistence/FINDINGS.md) — on why fixed-size padding buckets were rejected: *"a direct, specific trace that **deliberate anti-forensic countermeasures are running underneath the app**."*

Both are the team correctly catching a *design* risk before shipping it — good engineering. But the phrase "anti-forensic intent," written down under version control, is the more quotable risk of the two, independent of whether the design itself shipped.

---

## Tier 3 — User-facing copy naming law enforcement/government directly

`Docs/Features/Secure Mode/USER_GUIDE.md` — drafted as end-user help text. If this ships into the app or support site as-is, it's the most direct public statement in the repo naming a specific class of adversary by name rather than "someone who forces you":

- Line 100: *"Even law enforcement cannot decrypt them without your master PIN"*
- Line 221: section header *"Can Apple/Government Access My Data?"*

(Line 158, *"as strong as the passwords used by governments and military worldwide,"* is a strength comparison, not adversary framing — lower priority, included for completeness only.)

---

## Tier 4 — Roadmap/market-research language tying the product to defeating named U.S. government processes

Legitimate market-research citation (demand evidence) shades into positioning the roadmap around a specific government activity, not general personal safety:

- [`Docs/Features/Feature Ideation — 2026-07-10 Community Demand Pass.md:104`](../../Features/Feature%20Ideation%20%E2%80%94%202026-07-10%20Community%20Demand%20Pass.md) — *"The 2026 US domestic climate (ICE checkpoint device searches at airports, protest documentation guidance) has expanded the audience from 'border crossers' to residents who never leave the country."*
- Same file, line 69-74 — DV-advocacy sourcing paired with *"documenting ICE encounters and protest policing."*
- [`Docs/Features/Master Feature & Expansion Analysis.md:504`](../../Features/Master%20Feature%20&%20Expansion%20Analysis.md) — near-identical ICE/protest-policing framing.
- Same file, lines 62-63 (left unchanged in the Tier 1 pass) — *"Community demand: ...multiple border-crossing threads"* / *"Audience: Broad — anyone who crosses a border with a device."* Flagged in the Tier 1 conversation as lower-priority (market-research sourcing, analogous to citing FBI fraud stats elsewhere in the same doc) but not yet revisited.

---

## Recommended next step

Same as Tier 1: route through counsel before editing further, ideally in one pass rather than piecemeal — Tier 2's vocabulary question ("examiner" vs. "coercer" as the house style) and Tier 3's user-facing copy both have a real product/legal tradeoff (precision and defensibility of the threat model vs. exposure), not just a wording fix. Tier 4 additionally raises a business-writing question (is ICE/border-specific market sourcing itself worth keeping as internal rationale, separate from whether it should ever appear in anything public) that's as much a product-positioning call as a legal one.
