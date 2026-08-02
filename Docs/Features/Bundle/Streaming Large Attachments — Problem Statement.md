# Streaming Large Attachments Through the Bundle Format — Problem Statement

**Status:** Proposal — not scoped for implementation, not started
**Origin:** `Docs/Audit/SecurityReview2026-07-24/README.md`, finding #11 (unbounded inbound file read, SEC-5) — this document captures a follow-on question raised while fixing that finding, not the fix itself
**Related:** `Docs/Features/Bundle/SPEC.md` (v4 wire format — fixes size bloat, not memory), `Docs/Features/Import/Large Video Import — OOM Investigation.md` (proven streaming-encryption techniques, different layer), `Occulta/Services/Attachment+Manager.swift` (existing chunked at-rest format)

---

## 1. Problem

A bundle carrying a few large attachments (e.g. three 1 GB videos) forces the receiving device to hold the entire decrypted payload in memory at once, regardless of how the raw encrypted file was read off disk.

This was raised while fixing SecurityReview2026-07-24 finding #11: `OccultaApp.swift`'s inbound-file handler read the whole encrypted `.occ`/`.occbak` file into a heap `Data` via `URLSession.shared.data(from:)`, with no size bound. That specific read was fixed by switching to `Data(contentsOf:options:.mappedIfSafe)` (memory-mapped, OS-paged, no arbitrary cap — see the finding's "Fix applied" note and commit `7edef05`). That fix is complete for what it targeted. It does not touch the problem this document is about.

### Why the read-side fix doesn't help here

`OccultaBundle.ciphertext` is one atomic AES-GCM seal over the *entire* `SealedPayload` — message text, prekey batch, shard operations, and every `Basket.File.content` combined into a single plaintext blob before encryption (`ComposableMessage.swift` → `WireHandle.encode(basket:)` → `Manager.Crypto.seal`/`seal(message:groupID:recipients:)`). CryptoKit's `AES.GCM.open()` authenticates and decrypts that whole blob in one call — there is no partial or incremental decrypt. For three 1 GB attachments in one bundle:

1. The raw encrypted file is now mmap'd cheaply (fixed).
2. `AES.GCM.open()` still needs to produce a contiguous ~3 GB+ plaintext buffer in one shot to authenticate the message.
3. `WireHandle.decode(basket:)` / `JSONDecoder.decode(Basket.self)` then decodes that entire buffer into a `Basket` struct before any individual file is touched.
4. Only *after* all of that does `OccultaApp.buildOwnedBasket` start writing each `File.content` to the temp directory (already-existing behavior — this step is fine, it's just downstream of the spike).

Steps 2–3 are the actual bottleneck, and the mmap fix has no effect on them.

### The send side has the same shape of problem

Composing a message with a few 1 GB attachments almost certainly has the mirror-image issue: `Occulta.File.content` is a plain in-memory `Data` throughout `ComposableMessage.swift`'s compose pipeline, so the attachments are likely fully materialized before `seal()` ever runs. Not confirmed by code reading for this document — noted because a real fix has to be symmetric, not receive-side-only.

---

## 2. There's already a proven building block for this — one layer up

`Occulta/Services/Attachment+Manager.swift` implements a chunked AES-GCM format (magic `"OATT"`, informally `.eatt`) for **at-rest** attachment storage, once a file is already on the receiving device:

- 101-byte authenticated header (magic, version, chunk size, chunk count, plaintext size, base nonce, per-file HKDF salt, header HMAC)
- 256 KB chunks, each independently sealed with `AES.GCM` (its own derived nonce: base nonce XOR chunk index)
- `StreamingEncryptor`: `append()` accepts data incrementally, buffers at most one chunk (256 KB) before flushing to disk; `finalize()` writes the authenticated header
- `Decryptor.range(at:offset:length:)`: decrypts only the chunks a given byte range touches — this is what makes in-app video scrubbing possible without decrypting the whole file
- Proven in production: `Docs/Features/Import/Large Video Import — OOM Investigation.md` documents driving a 2 GB video import from ~3 GB of peak memory (multiple failed approaches) down to a flat ~90 MB, using this exact format plus `F_NOCACHE`/`F_RDAHEAD=0` on the source file descriptor.

This is the right reference design for the *wire transport* problem too — not a new scheme to invent from scratch, but the same chunk-header/HKDF/derived-nonce approach applied to `OccultaBundle` instead of local storage.

One relevant gap even at the current at-rest layer: `OccultaApp.buildOwnedBasket` calls `AttachmentManager.encrypt(content:to:)` (the one-shot `Encryptor.write`, line ~665) rather than `streamingEncryptor(to:)` + `append()`, because `content` is already a single in-memory `Data` by the time it gets there — a symptom of the same root problem, not a separate bug.

---

## 3. Proposed direction (sketch, not a spec)

Split the bundle's encrypted payload into two parts instead of one atomic blob:

- **Manifest** — message text, per-file metadata (name, extension, size, ordering), and per-file key-derivation material (salt, base nonce). Small, always cheap to decrypt first, authenticated as its own unit.
- **Per-file chunked ciphertext** — each attachment encrypted independently using the `.eatt`-style scheme (chunk size, derived-per-chunk nonce, per-file HKDF key from the same session/contact key material already used elsewhere in the bundle).

Receive path becomes: decrypt manifest (cheap) → for each file, decrypt-and-write chunk by chunk directly to its destination path, discarding each chunk's plaintext immediately after writing. Peak memory becomes bounded by chunk size, not attachment size or bundle size.

An open question worth resolving during actual design (not here): whether a received file's transport-chunk ciphertext could be **re-keyed chunk-by-chunk** directly into the local `.eatt` at-rest format without ever fully materializing the plaintext — i.e. decrypt one transport chunk, immediately re-encrypt it under the local file key, write, discard, repeat. If the chunk sizes and structures are made compatible on purpose, this could avoid a full plaintext pass entirely for the receive→store transition. Speculative; needs real design attention before assuming it's viable (transport chunk boundaries and at-rest chunk boundaries have no reason to align unless deliberately designed to).

---

## 4. What a real design pass would need to resolve

- **Wire format versioning.** This is wire-breaking, same category as v4 (see `SPEC.md` §3). Needs its own version/mode and a compatibility story for contacts still on the current one-blob format — almost certainly "fall back to today's format when the peer hasn't demonstrated support," mirroring the capability-watermark pattern already used for `.groupCapable`/`.senderSignatureCapable` in `OccultaBundle.Version`.
- **Per-chunk AAD / anti-truncation.** Each chunk's authentication must bind its index and whether it's the final chunk, or an attacker who drops trailing chunks could produce a validly-authenticated *truncated* file. The existing `.eatt` format's `chunk_count` in the authenticated header covers this for at-rest storage (a short read is detected against the header) — the transport equivalent needs the same property enforced against a malicious peer, not just corruption.
- **Send-side streaming reads.** A real fix needs the compose pipeline to read source attachments incrementally too (Photos/Files), not just accept a pre-materialized `Data`. `Large Video Import — OOM Investigation.md` already worked out the hard parts of this for local Photos import (`PHAssetResourceManager` delivers arbitrarily large chunks with no control; `mmap` + `MADV_DONTNEED` is unreliable on Darwin for bounding physical memory; POSIX `read()` with `F_NOCACHE` + `F_RDAHEAD=0` on the *source* fd is what actually worked) — those lessons transfer directly to reading attachment sources for composing a bundle, but composing over UWB/BLE (not local disk-to-disk) adds its own transport-timing considerations not covered by that investigation.
- **Rust portability.** `SPEC.md` §12 already commits the wire format to being the authoritative spec for a future Rust `occulta-protocol` implementation. Any change here needs the same discipline (fixed-width fields, documented endianness, cross-platform AAD test vectors).
- **Test plan.** At minimum: truncation/reordering rejection per file, backward compat against a peer still on the one-blob format, and a memory-bounded regression test analogous to what the OOM investigation used to validate the at-rest path (flat RSS across a multi-GB synthetic bundle).

---

## 5. Explicitly out of scope for this document

- No implementation decision has been made. This is a problem statement plus a pointer to the closest existing analog in this codebase, written down so the next person scoping it doesn't start from zero.
- Not a replacement for or amendment to `SPEC.md` (v4) — that spec is shipped/implemented status for the size-bloat fix; this is a distinct, later problem.
- Not part of SecurityReview2026-07-24's remaining findings — that review's finding #11 (unbounded read) is fixed; this is bigger than what that finding asked for.
