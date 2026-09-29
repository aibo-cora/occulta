# Storage Layering — Vault, Recovery, and the BEK

**Superseded 2026-09-02, four hours after being written.** Split back into two documents along the
actual technical seam — which container a given piece of work touches — rather than kept as one:

- [`VAULT_KEY_LAYERING.md`](VAULT_KEY_LAYERING.md) — vault entries and the BEK record, sealed under
  the vault's biometric-gated key. Bug 105 lives here.
- [`RECOVERY_BUFFER_LAYERING.md`](RECOVERY_BUFFER_LAYERING.md) — the shard buffer and restore/arming
  state, sealed under the non-biometric recovery buffer key. Bugs 93/95/99/100/101 live here.

They're independently buildable except at one join point (restore completion, which reads the second
and writes the first) — each doc names it at the point of contact rather than requiring both to be
read together for every decision, which is what this merged version turned into.

This file's predecessor, `BEK_LAYERING_REFACTOR.md` and `AT_REST_LAYERING.md`, were merged into this
one; this one is now split by a different, better boundary. Kept as a redirect, not deleted, so
anything still pointing at this path lands somewhere useful.
