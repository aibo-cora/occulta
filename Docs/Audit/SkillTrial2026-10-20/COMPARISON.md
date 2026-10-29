# Cloudflare security-audit skill: trial on `v2.0.0/introduction-cards`

How the skill's trimmed quick run on the branch diff (`3319fd7...8c51ad97`) compares with the reviews
already recorded on the branch (comparison-baseline.md). Lead numbers refer to NEEDS-VALIDATION.md.

## What ran

- Recon: 5 Opus agents. Occulta's threat model was added to Phase 1, overriding the skill's rule that same-account access is self-impact.
- Hunting: 13 Opus hunters over 23 units. 9 returned; 4 were stopped by usage limits and deferred.
- Critic: none.
- Verification: 6 Sonnet verifiers, in batches of 2–4 candidates.
- No target code ran, so nothing could be `confirmed`. Every surviving candidate is `needs_validation`.
- Cost: at least 4.5M tokens reported by agents, plus segments lost to three usage-limit stops, which weren't reported.

Result: 20 candidates, of which 18 survived independent review and 2 were rejected.

## The comparison can't measure recall

Every baseline finding (R1–R14, P1–P4, B153–B168) was fixed before `8c51ad97`, the commit audited. A
review of fixed code can't re-find them. So this run shows whether the skill finds things the reviews
didn't. It doesn't show whether it would have found what they did.

Measuring that means running it on a commit before the fixes, for example `e25ad4b^`, at similar cost.

## What it found that the reviews didn't

### Gaps at the edges of earlier fixes (5)

These are the most credible class: each sits right next to something a review already fixed.

| Lead | Earlier fix it extends |
|---|---|
| #10: last-resort and long-term card slots route to the first holder | R9 routed by the prekey a slot names, but that covers one-time prekey IDs only |
| #9: tampering with the outer header burns a one-time prekey | B165 bound each slot to the body digest, but not to the outer header |
| #18: equal-date replay of the newest batch after the sender's clock goes back | P3 (`d0fb4633`) refused old batches. The strict `<` lets the newest date through, and it meets B158's residual |
| #2: approving a hidden contact's challenge at a duress depth signs and seals a reply to them | Same class as R1/R8, which closed this for cards. Bug 40's guard (`passSecurityControl`) was removed in `b1f9045f` (2026-08-08) under the presence-oracle decision, which covers showing, not replying. Likely a regression |
| #15: the contacts list's empty state and trust summary read the unfiltered query | R1 fixed open requests in the same file |

### New, in neither the reviews nor the known-limitations list (11)

- **Crafted-file traps before authentication:**
  - #5: a 167-byte `OCCB` file traps on its length field;
  - #1: a negative `custodyManifestCount` traps `openGroup`;
  - #4: an out-of-range `SignedAttribute` date traps signature verification.

  Register D6 (no fuzzing) predicts this class; these are concrete instances.
- **Duress isolation:**
  - #16: a group draft written at the real depth shows at a duress depth;
  - #17: group capacity and picker eligibility count hidden members;
  - #3: challenge state survives `endSession`.
- **Forensic:**
  - #7: card-contact and group attachments are staged and kept as drafts in plaintext;
  - #8: Erase All Data leaves drafts and draft attachments. `74b99161` fixed the share staging key on erase after the audited commit, but not drafts.
- **Card lifecycle:**
  - #13: replies seal to a revoked device's prekeys;
  - #14: inherited shard state hard-blocks every card send.
- **Key derivation:** #6, the share staging key, is a function of a public point. See the next section.

### Owner decisions, not defects (2)

#11 (re-opening a hidden contact's retained files at a duress depth) and #12 (error text separating
"hidden sender" from "unknown sender") sit just outside the accepted presence-oracle decision. Whether
that decision extends to them is yours to make.

### Found in parallel with the team (2)

The never-swept `inbound/` handoff files and Erase All Data skipping the share staging key. Hunters
flagged both; `9e7e9157` and `74b99161` fixed both after the audited commit.

## The lead most worth settling: `ECDH(d, G)`

Lead #6 found that the share staging key is derived as `ECDH(SE key, G)`. That equals a function of
the public key `Q` (cofactor 1, so `d·G = Q`). The same "Enclave component" appears in:
- the vault key (`Key+Manager.swift:719-740`);
- the shard-custody key (`:819-839`);
- the PIN key;
- one half of the local DB key (`:150-172`, `:438`). The hybrid local DB key also has a keychain-random half, so it is less exposed.

The docs assume the opposite:
- `PASSPHRASE_LAYER_KEYS.md:78-92` calls this half device-binding.
- `PROTECTION_ASSESSMENT.md` says every passphrase guess costs an Enclave call.

If `Q` can be recovered from an extraction, or obtained in-process, without an Enclave operation, then:
- the vault's biometric gate doesn't protect the vault key's secrecy;
- the planned layer keys' "SE half" adds no secrecy.

This is unverified. The deciding fact is whether `Q` is recoverable that way. A Simulator test can settle
it: derive the key from `Q` alone and compare.

## Noise and misses

- **Rejected:** 2 of 20. The basket file URL can't name a deletable path. The reflection gains a redeemer nothing.
- **Narrow:** several survivors are low impact (#10, #13, #18).
- **Not covered:** exchange/meeting, CI, vault/migration, wildcard, and the final critic, all from the trim.
- **Not re-found:** open baseline items B162 and B167, because the known-limitations list excluded them on purpose.

## Verdict

With Occulta's threat model added, the skill produced:
- leads the branch reviews didn't, including gaps at the edges of five earlier fixes;
- a likely regression of Bug 40;
- one question about the key hierarchy that may be fundamental.

Most leads are duress or forensic. The stock skill's same-principal rule would have dropped exactly
those, so the adaptation mattered.

Against that: it can't confirm anything without running tests, recall is unmeasured, and the cost is
high. Worth using on a release diff with:
- the threat-model brief;
- Sonnet hunters;
- a token budget;
- you running the leads' Simulator tests afterwards.

Not worth using as a standing replacement for the current review process.
