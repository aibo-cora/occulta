# Streamed Bundle Bodies — Specification

**Status:** Approved for implementation, 2026-10-23. Stages 1–4 implemented on `v2.0.0/streaming-bundles`: `STREAMING_MIGRATION_NOTES.md` records each stage's migration and where the code departs from this text. Every stage ships in 2.0.0 (§12).
**Replaces:** `Streaming Large Attachments — Problem Statement.md` (this is its design)
**Extends:** `SPEC.md` (v4 wire format). Everything in that document not changed here still holds.
**Related:** `Docs/Features/Group Messaging/SPEC.md`, `Docs/Features/Import/Large Video Import — OOM Investigation.md`,
`Occulta/Services/Attachment+Manager.swift` (the at-rest `.eatt` format), `bugs.md` Bugs 165, 181, 183, 184

---

## 1. Problem

Opening a bundle with an ~800 MB video kills the receiving app before the message appears (`bugs.md` Bug 183).
The body is one AES-GCM seal over everything: metadata, message text and every attachment. Nothing can be shown,
or written out, until all of it has been decrypted into one buffer.

Peak memory on receive, for an attachment of size *S*:

| Step | Where | Resident |
|---|---|---|
| Inbound file mapped and read through | `OccultaApp` inbound handler | *S* (file-backed) |
| Slot check opens the whole body, result discarded (Bug 181) | `openRecipientSlot` | *S*, then freed |
| Body opened again | `openGroup` → `openGroupCiphertext` | *S* |
| Each attachment sealed to `tmp/` | `buildOwnedBasket` → `AttachmentManager.encrypt` | *S* more before PR #132; one chunk after it |

The send side is worse. `AttachmentManager.data(at:)` decrypts each staged attachment in full (twice its size while
it is assembled). `WireHandle.encode(basket:)` copies it. `AES.GCM.seal(...).combined` makes the ciphertext and
copies it, and `WireHandle.encode(_:)` copies it again. That is roughly 4*S* resident at once.

## 2. Goals

1. Peak memory for a bundle body on either side is bounded by a few chunks, whatever the attachment size.
2. The receiver shows the message text and attachment list before any attachment is decrypted.
3. An observer of a bundle learns nothing it doesn't learn today (§9).
4. The send and receive sides share one chunk codec and one set of file-I/O helpers (§8).
5. Contacts on older builds keep receiving bundles they can read. Bundles from older builds keep opening.

Out of scope: the legacy single-recipient formats (`.v3fs`, non-group `.v4`). They are only ever sent to builds
older than 1.9.0. A memory guard covers them (§7).

---

## 3. Where the new layout is used

Only **group-mode** bundles (`Mode.group`) use the streamed layout. Since 1.9.0 that is every send:

- one-to-one messages, through the single-recipient group envelope;
- named groups;
- introduction-card conversations;
- identity challenges and responses sent at `.bodyDigestCapable` or above.

A send uses the streamed layout only when **every** recipient resolves to `.streamedBodyCapable` (§10). Otherwise it
uses today's inline layout, under the memory guard (§7). There is no size threshold: one layout for all bundles to a
capable recipient set, so the layout says nothing about the content.

Card conversations always use the streamed layout. Introduction cards exist only in 2.0.0 and later, so every card
peer is at the tier (§10.3).

---

## 4. Wire layout

All integers are big-endian, as in `SPEC.md` §4.

### 4.1 Outer envelope

The 167-byte header of `SPEC.md` §4.1 is unchanged except for two bytes:

| Offset | Field | Inline layout | Streamed layout |
|---|---|---|---|
| 4 | `version` | `0x04` | `0x0A` |
| 5 | `min_reader_version` | `0x04` | `0x0A` |

`ciphertext_length` (offset 159, `u64`) is the length *T* of the chunk stream (§4.3). The chunk stream sits where
the AES-GCM combined ciphertext sits today. The TLV sections follow it, unchanged. Section `0x01` (group envelope)
is mandatory for the streamed layout.

**Reader rules.** These replace `SPEC.md` §10 rule 3 for builds with this spec.

1. Accept exactly `0x04` and `0x0A` as `version`. Throw `BundleError.unsupportedVersion` for anything else,
   including `0x05`–`0x09`. Those bytes exist only as capability markers. Today they are rejected because
   `min_reader_version` equals `version` and exceeds `0x04`. Once readers accept up to `0x0A`, that check alone no
   longer rejects them, and `byteToVersion` would map them to tiers that `buildOwnedBasket` routes to the legacy
   trial-decryption path.
2. `min_reader_version` must equal `version`.
3. A streamed bundle without a group envelope throws `BundleError.malformedBundle`.

Builds before this spec compare `min_reader_version` with `0x04`. They reject a streamed bundle with
`unsupportedVersion` ("requires a newer version of Occulta"), before any key is derived or prekey touched.

### 4.2 Plaintext stream

The plaintext that the chunk stream encrypts, of length *P*:

```
Offset    Size   Field
──────    ────   ───────────────────────────────────────────────────────────────
0         4      manifest_length: u32          (M; 1 ≤ M ≤ 16 MiB)
4         M      manifest                      (§4.4)
4+M       L₁     content of streamed file 1    (manifest order)
…         …      …
          Lₖ     content of streamed file k
```

*P* = 4 + *M* + Σ*Lᵢ*, exactly. A receiver that reaches the final chunk with bytes left over, or with a file still
short, rejects the bundle (§5.3).

File boundaries exist only inside the encryption. On the wire the stream is uniform fixed-size chunks (§9).

### 4.3 Chunk stream

The STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár, 2015), as used by age and Tink, over AES-256-GCM.

**Constants.**

- `C` = 262,144 bytes of plaintext per chunk. This is the same value as `Encryptor.chunkSize` for `.eatt`, and one
  constant serves both.
- Tag 16 bytes. Nonces are not transmitted.

**Chunking.** *n* = ⌈*P* / *C*⌉ (*P* ≥ 5, so *n* ≥ 1). Chunk *i* < *n*−1 carries *C* plaintext bytes. The last
carries *P* − (*n*−1)*C* bytes, between 1 and *C*. A *P* that is a multiple of *C* ends on a full final chunk, never
an empty trailer.

On the wire chunk *i* is `ciphertext ‖ tag`, chunks back to back, so *T* = *P* + 16*n*. A reader derives *n* and
the last chunk's size from *T*. It rejects a *T* whose last chunk would be shorter than 17 bytes.

**Key.** One key per bundle:

```
streamKey = HKDF-SHA256(ikm: sessionKey, salt: empty, info: "occulta-body-stream-v1", length: 32)
```

`sessionKey` is the group session key: random per bundle, wrapped in every recipient slot. It also keys the
`senderProof` HMAC, hence the derivation.

**Nonce.** For chunk *i*: `0x00000000 ‖ u64(i)`, 12 bytes. Deterministic nonces are safe because `streamKey` is
fresh for every bundle and each index is sealed once.

**AAD.** For chunk *i*:

```
headerAAD ‖ u64(i) ‖ u8(final)          final = 0x01 for chunk n−1, else 0x00
headerAAD = utf8("streamedBodyCapable") ‖ sortedKeysJSON(outerSecrecy) ‖ blind
```

`headerAAD` is `OccultaBundle.computeAdditionalAuthentication(version: .streamedBodyCapable, secrecy:)` followed by
`blind`. It is today's group outer AAD with the new version's raw value, computed by the same function.

What this gives:

- **Header authenticated by every chunk.** The Bug 181 check needs only chunk 0.
- **Truncation rejected.** A stream cut short ends on a chunk sealed with `final = 0`.
- **Extension rejected.** A stream with chunks added fails on the extra bytes.
- **Reordering rejected.** Each index is bound into the AAD.
- **No splicing between bundles.** Each bundle has its own key.

### 4.4 Manifest

`manifest` is `WireHandle.encode(payload:)` of the bundle's `SealedPayload`: the same metadata JSON, the same
`senderProof`, `groupID` and `appVersion`. Its `message` is `WireHandle.encode(basket:)` of the basket, with one
change:

- Every file of format `.file` is **streamed**. The basket carries it with `content_length = 0`. Its `FileMeta` JSON
  gains `"streamedLength": Lᵢ`, the plaintext length of its content in §4.2, which may be 0.
- `.text`, `.contacts` and `.link` files stay inline, as today. They are bounded by the 16 MiB manifest cap.

This matches the split `buildOwnedBasket` already makes: `.file` content goes to disk, everything else stays in
memory. Streamed files appear in §4.2 in the order the basket lists them.

`FileMeta` is private to `WireHandle`. The new key is optional, so the existing codec reads and writes both layouts.
A sender whose manifest would exceed 16 MiB refuses the send. A receiver rejects `manifest_length` > 16 MiB before
decrypting past it.

### 4.5 Recipient slots

The slots, `RecipientPayload`, and the group envelope encoding are unchanged.

- **Body digest.** `bodyDigest` is SHA-256 over the *T* bytes of the chunk stream: the `ciphertext` field, as today.
  For the streamed layout it is mandatory. A slot without it fails with `GroupDecryptError.missingBodyDigest`,
  whatever tier is recorded.
- **Writing order.** The sender computes the digest while writing the stream and appends the envelope afterwards.
  The envelope already comes after the body on the wire.

---

## 5. Receive

### 5.1 Opening the file

The inbound handler opens the file as a read handle with `F_NOCACHE` and `F_RDAHEAD = 0` (§8.2), never memory-mapped.

- **Bug 101 deletion.** The copy iOS made in our container is unlinked as soon as the handle is open. The open
  handle keeps it readable.
- **Size check.** A file shorter than 167 bytes is rejected.
- **Dispatch on the version byte.**
  - `0x0A` takes the streamed path below.
  - Anything else is read into a mapped `Data`, as today, and takes the inline path, after the memory guard (§7).
- **Introduction cards.** A card is exactly 1,768 bytes, checked before any bundle decoding, from the file's size and
  bytes. This is unchanged.

The Secure Mode queue (`pendingFileData`) holds the open handle in place of mapped bytes. Both unlock paths drain it
exactly as they drain the bytes today.

### 5.2 Order of operations

Every step before 5 runs before any prekey is recorded as used, exactly as today.

1. **Parse.** Parse the header from bytes 0–166. Read the TLV sections from offset 167 + *T* to the end of the file,
   capped at 8 MiB. Parse the group envelope.
2. **Identify the sender** by fingerprint. This is unchanged.
3. **Open our slot.** Trial-decrypt the slots and open ours (`openRecipientSlot` / `openCardSlot`). This is
   unchanged, and gives `sessionKey` and `bodyDigest`.
4. **Pass 1, digest.** Hash the chunk stream from disk and compare with `bodyDigest`. A mismatch throws
   `bodyDigestMismatch` (Bug 165).
5. **Header check (Bug 181).** Open chunk 0 under `streamKey`. This replaces the full `openGroupCiphertext` in
   `openRecipientSlot` and in card recognition. The prekey is recorded as used from here, as today.
6. **Manifest.** Open chunks in order until 4 + *M* plaintext bytes are buffered. Decode the manifest as a
   `SealedPayload`. Every check `openGroup` runs today runs on it unchanged:
   - the identity-challenge rules (5.1);
   - the digest and signature tier gates;
   - the sender proof;
   - `updateMaxVersion`, `acceptInboundBatch` and `replenish`;
   - the save.
   Identity challenges and shard-only bundles leave here, as today.
7. **Show the message.** The depth gate in `buildOwnedBasket` runs, unchanged. Then the message sheet shows the
   inline files and one placeholder per streamed file.
8. **Pass 2, attachments.** Opening continues from where step 6 stopped. Bytes after the manifest go, in manifest
   order, into one `StreamingEncryptor` per streamed file, written to `tmp/<UUID>.<sanitised extension>`.
   - **Key.** Each file is sealed under the received-attachment key (§6).
   - **Completion.** A file is finalised and its placeholder replaced when its last byte is written.
   - **Final check.** After the final chunk, the bytes routed must equal *P* exactly.

Memory throughout: one plaintext chunk, one ciphertext chunk, the manifest, and one `StreamingEncryptor` buffer.

### 5.3 Failure and cancellation

- **Failure in pass 2** (a chunk fails to open, the stream ends early or late, or a write fails): delete every
  temporary file of the message, including completed ones, and replace the placeholders with one error. A failure
  here means the sender built a bad body or the file changed under us. Step 4 already ruled out anyone else.
- **Cancellation.** Pass 2 checks for cancellation at every chunk. These cancel it and delete the message's
  temporary files:
  - the sheet closes;
  - the session ends (`endSession`, `sessionEpoch`, Bug 148);
  - the app goes to the background past the grace period.
- **The prekey stays spent** in every case above. Today's rule (Bug 148, `decisions.md`) is unchanged.
- **Crashes.** A crash mid-stream leaves sealed partial files in `tmp/`. They are under a key, and the launch-time
  `clearTemporaryDirectory()` removes them.

### 5.4 Body consumers

Four places open a group body today. Each takes `bundle.ciphertext` as `Data`:

- `openRecipientSlot`: digest check and the Bug 181 open;
- `openGroup`: the open;
- `openCardSlot`: digest check and open;
- the card first-message recognition in `ContactManager+Cards.swift`: digest check and open.

All four go through one `BundleBody` value with two implementations:

| Operation | Inline | Streamed |
|---|---|---|
| `digest()` | `SHA256(ciphertext)` | pass 1 (§5.2 step 4) |
| `authenticateHeader(sessionKey)` | `openGroupCiphertext`, result discarded | open chunk 0 |
| `openManifest(sessionKey)` | `openGroupCiphertext` + `decode(payload:)` | §5.2 step 6, returns a cursor |
| `streamFiles(cursor, sink)` | the files already in the decoded basket | §5.2 step 8 |

The checks themselves stay where they are, written once, and work on both layouts.

---

## 6. Received-attachment key (Bug 184)

`buildOwnedBasket` seals received files under `fileEncryptionKey(for: owner)`. If that throws, it writes them with
`writeProtected`, which is plaintext in `tmp/`. `fileEncryptionKey` throws `contactHasNoKeys` for any sender we hold
no public key for, an introduction-card contact not yet met in person among them. The message sheet builds its
reader the same way, so a fix must change both.

Both ends use one resolver: the contact's file key, else the compose staging key
(`ShareStagingKeyManager.deriveComposeStagingKey`, as `ComposeViewModel` already does for sends). If neither is
available, the attachment is dropped with an error. It is never written in plaintext. This ships in stage 1,
before the streamed layout, and fixes the inline path too.

---

## 7. Memory guard for the inline layout

The inline layout still holds whole bodies in memory. It is needed for:

- contacts whose tier we haven't recorded yet, before their first message from 2.0.0;
- groups with a member below the tier;
- bundles from builds older than this spec.

Before the one-shot work, compare the estimate with `os_proc_available_memory()`:

| Side | Estimate | On failure |
|---|---|---|
| Receive | 2*T* + 64 MiB | `BundleError.tooLargeForDevice`; "too large to open on this iPhone" |
| Send | 4*P* + 64 MiB | refuse the send; "too large to send until the recipient updates" |

The guard refuses outright; there is no "try anyway". A refusal changes nothing: no prekey taken, nothing written.
The messages name no contact or depth, and the guard behaves the same at every depth.

---

## 8. Shared code

The goal is one implementation of each piece, used by both directions, and by the at-rest format where it fits.

### 8.1 `OccultaFormats` (pure, no I/O, Swift 6, nonisolated)

New file `BodyStream.swift`:

| Piece | Send | Receive |
|---|---|---|
| `BodyStream.chunkSize`, `streamKey(sessionKey:)`, `nonce(index:)`, `aad(header:index:final:)` | ✅ | ✅ |
| `BodyStream.Layout`: *P* ↔ *T*, *n*, last chunk size, validation | ✅ | ✅ |
| `BodyStream.Sealer`: `append(plaintext)` → emits sealed chunks; `finish()` seals the final one; running SHA-256 of what it emitted | ✅ | |
| `BodyStream.Opener`: `open(chunk, index)` against the layout; refuses out-of-order and post-final input | | ✅ |
| `BodyStream.Manifest`: frame/unframe §4.2's header, on top of `encode(payload:)` / `encode(basket:)` with `streamedLength` | ✅ | ✅ |

`Sealer` and `Opener` call one internal `seal(chunk:index:final:)` / `open(...)` pair, so nonce and AAD derivation
exist once. Both buffer through one `ChunkBuffer` (fixed-size accumulation, the logic in
`StreamingEncryptor.append` today), which `StreamingEncryptor` also adopts. The `.eatt` format doesn't change: only
its buffering moves.

`WireHandle.parse` and `WireHandle.encode(_:)` are each split in two:

- `parseHeader(_:)` / `encodeHeader(_:ciphertextLength:)` for the 167-byte header;
- `parseSections(_:)` / `encodeSections(_:)` for the TLVs.

The in-memory functions become those two calls around the ciphertext, so inline bundles stay byte-identical. The
streamed reader and writer call the same halves around the chunk stream.

### 8.2 App target

| Piece | Used by |
|---|---|
| `NoCacheFile.reader(url)`: `F_NOCACHE` + `F_RDAHEAD = 0`, `read(at:count:)`, `forEachChunk(range:size:)` | receive passes 1 and 2; send reading staged files; `sealInPlace`; the POSIX import loop in `ComposeViewModel` |
| `NoCacheFile.writer(url)`: created with `.complete` protection, `F_NOCACHE`, excluded from backup, deleted on any error | the `.occ` writer; `Encryptor.write` (PR #132); `StreamingEncryptor` |
| `Decryptor.forEachChunk(at:)`: yields each `.eatt` chunk's plaintext in order; `range` reimplemented on it | send: reading staged attachments |
| `StreamingEncryptor` | receive pass 2; share-extension staging |
| `BundleBody` (§5.4) | the four body consumers |
| `BundleWriter`: header → `Sealer` → sections, through `NoCacheFile.writer` | every send |

### 8.3 Send

`Manager.Crypto.seal(sealedPayload:groupID:recipients:senderIdentity:)` keeps its steps but gains a streamed variant.
That variant takes a destination URL and the streamed sources, and writes the bundle there:

1. Generate the session key, blind and sender proof, and build the manifest. This is unchanged.
2. Compute *P* and *T*, and write the header through `BundleWriter`.
   - Each source's length comes from its `.eatt` header (`plaintextSize`), with no decrypting.
3. Stream the body.
   - Feed the `Sealer` the manifest framing.
   - Feed it each source through `Decryptor.forEachChunk`.
   - The sealed output goes to the file and the hash.
4. Wrap the slots with the digest using the unchanged `wrapRecipient`, and append the sections.

`encryptBundle`, `encryptGroupBundle` and `encryptCardBundle` take a destination URL instead of returning `Data`. The
prekey handling around them is unchanged, including when the record is saved.

Callers:

- **Compose.** One-to-one and group compose in `ComposeViewModel`, and sends from drafts, already hold staged `.eatt`
  files and pass them through.
- **Share extension.** `encryptShareSession` passes the share session's files (§8.4).
- **Identity challenges.** The coordinator passes no streamed files, only a manifest.

### 8.4 Share extension

The extension stages each file as one AES-GCM blob under the share key. To do that it reads the whole file into the
extension's memory (`Data(contentsOf:)`, capped at 100 MB), and `ShareSession.load` decrypts every file into the
app's memory.

- **Extension.** The extension stages `.eatt` through `StreamingEncryptor`, keyed by
  `ShareStagingKeyManager.deriveSymmetricKey()`. It streams from `loadFileRepresentation`'s URL in 64 KB reads, as
  `ComposeViewModel.seal(contentsOf:to:using:)` does.
- **App.** The app passes the staged files to the streamed send as sources, as compose does.
- **Size cap.** The 100 MB cap stays until the extension's peak memory is measured on a device.
- **Migration.** A session staged by the previous build, in flight at upgrade, is read with today's one-shot
  decrypt. `AttachmentManager.isSealed` tells the formats apart. Sessions are deleted after use or cancel, so the
  legacy reader can go in the next release.

---

## 9. What an observer learns

**Bundle on the wire.** An observer sees the header, *T*, and the group envelope.

- **Size.** *T* gives *P* exactly, as the combined ciphertext's length does today. Chunks are fixed-size and file
  boundaries are inside the encryption, so the number of attachments, their sizes, and the text length are not
  visible. Today only the total is visible too.
- **Version byte.** `0x0A` says the sender runs 2.0.0 or later. `0x04` already separates 1.8.2+ from older senders,
  and the envelope separates 1.9.0+. This is the same kind of information.

**The receiving phone.** It holds the following, at every depth:

- **Attachments.** Only sealed `.eatt` files in `tmp/`, under a key (§6). Partial files are deleted on failure or
  cancel, and swept at launch after a crash.
- **The inbound file.** Unlinked on open. While unlocked, its bytes stay on disk only while the handle is open, as
  the mapping keeps them today.
- **Processing.** Every step of §5.2 depends on the file and the keys, never on the depth. The depth gate is the
  same one as today.

**The sending phone.** The `.occ` written to `tmp/` is ciphertext, with `.complete` protection, excluded from
backup, and deleted when the share sheet closes. This is unchanged.

---

## 10. Compatibility

### 10.1 New tier

`OccultaBundle.Version.streamedBodyCapable`:

| | |
|---|---|
| Marker byte (`maxBundleVersion`) | `0x0A` |
| Wire `version` byte | `0x0A` (the first tier since `.v4` that is also a wire version) |
| `minimumAppVersion` | `"2.0.0"` |
| Position in `known` | first, above `.bodyDigestCapable` |

What changes with it:

- **Tier lookup.** `max(forAppVersion: "2.0.0")` returns `.streamedBodyCapable`, and `isAtLeast(.bodyDigestCapable)`
  still holds.
- **Byte tables.** `wireByte`, `_byteToVersion`, `_versionToByte` and `highestKnownWireByte` are updated together,
  per the warning on those tables. `everyTierRoundTripsThroughItsMarkerByte` pins them.

### 10.2 Choosing the layout

- **Ordinary sends.** Streamed when every recipient resolves to `.streamedBodyCapable`, otherwise inline.
  Resolution is `resolveTargetVersion`, unchanged. An unrecorded or stranded marker resolves below the tier, so it
  gets inline.
- **Mixed groups.** A named group with any member below the tier is sent inline, under the guard.

### 10.3 Cards

`encryptCardBundle` always uses the streamed layout. Cards exist only from 2.0.0, so no card peer runs an older
build. The receiving side accepts either layout from a card contact.

### 10.4 Convergence

Convergence is as in `SPEC.md` §6.4. A contact's first message from 2.0.0 raises their tier, and the sends after it
are streamed. Until then the guard keeps an oversized inline bundle from crashing either side.

---

## 11. Tests

**Codec (`OccultaFormats`, runs anywhere):**

- **Round trip.** At *P* = 5, *C*−1, *C*, *C*+1, 3*C*, and 3*C*+17.
- **Manifests.** An empty basket, text only, many small files, a zero-length streamed file, and a streamed file
  ending exactly on a chunk boundary.
- **Rejected:**
  - a dropped final chunk;
  - an appended chunk;
  - a swapped pair;
  - a chunk from another bundle;
  - a forged final flag;
  - a non-final chunk presented last;
  - each header byte flipped;
  - `manifest_length` over 16 MiB;
  - bytes left over or missing at the end;
  - a *T* whose last chunk is under 17 bytes.
- **Parsing.** `version` `0x05`–`0x09` is rejected, and so is a streamed bundle without a group envelope.
- **Inline bytes unchanged.** The split `parse`/`encode` leaves inline bundles byte-identical. The existing interop
  vectors pass unchanged.

**Interop vectors.** These pin the format byte for byte:

- `streamKey` derivation;
- nonce and AAD for chunk 0 final, chunk 0 non-final, and chunk 1;
- a complete streamed body for a fixed session key and inputs;
- the manifest framing.

**Receive and send (app):**

- **Prekey safety.** A bad digest leaves the prekey unused (Bug 165), and so does an altered header (Bug 181), on
  both layouts.
- **Partial results.**
  - A pass-2 failure deletes every temporary file and keeps the prekey spent.
  - Cancellation at each trigger in §5.3 deletes the temporary files.
- **Layout choice.**
  - A mixed-tier group is sent inline.
  - A card send is streamed.
  - An inline bundle from a pre-spec sender still opens.
- **Received-attachment key (§6).** A key-less sender's attachment is sealed on disk, with no plaintext marker in
  `tmp/`, and opens in the sheet.
- **Share extension.** A share session staged by the previous build still sends.
- **Memory guard.** It refuses with nothing taken or written. This uses an injectable `os_proc_available_memory`.
- **Depth.** The receive flow is the same at every depth: same steps, same files, same errors.

**Memory regression.** A synthetic 1.5 GB bundle is sent and received in the Simulator. The phys-footprint delta,
from `task_info`, must stay under 64 MiB on each side.

**Enclave.** Tests that create prekeys follow `CLAUDE.md`. Use `.enabled(if: secureEnclaveAvailable())` where
`PrekeySecretsManager` is reached, and inject keys everywhere else.

## 12. Delivery

All stages ship in 2.0.0.

| Stage | Contents | Depends on |
|---|---|---|
| 1 | §6 received-attachment key (Bug 184); §7 memory guard | — |
| 2 | §8.1 codec, `WireHandle` split, interop vectors | — |
| 3 | §8.2 I/O helpers; §5 receive path; the four body consumers | 2 |
| 4 | §8.3–8.4 send path, share extension, tier activation | 2, 3 |

Stages 1 and 2 are independent. PR #132, which writes `Encryptor.write` chunk by chunk, lands first: stage 3 builds
on its writer.

**Release rule.** `.streamedBodyCapable` is keyed on app version 2.0.0, like `.bodyDigestCapable`, so the same rule
applies (`ROLLOUT_PLAN.md`). No build numbered 2.0.0 or later may go out without stages 3 and 4, TestFlight
included. Such a build would be recorded at the tier and sent bundles it can't open, and only its own users would
notice.

`release/v2.0.0` was still at `MARKETING_VERSION = 1.11.1` on 2026-10-23. Stage 4 merges before the number changes.

## 13. Migration

No stored data changes format:

- **Received messages** are temporary: their files live in `tmp/` and are deleted when the sheet closes.
- **The at-rest `.eatt` format** is unchanged, so drafts and staged compose files carry over.
- **Capability markers** gain one value. Older values keep their meaning, and contacts move up on their next message.
- **Share sessions** staged by the previous build are read by the legacy path (§8.4).

A downgrade to a build without this spec (TestFlight, sideload only) leaves recorded `0x0A` markers. That build
reads them as "newer than us", per `bundleVersionState`, which is today's behaviour for any unknown byte.

## 14. Rust portability

Additions to `SPEC.md` §12:

- **STREAM.** The chunk stream is plain STREAM over AES-256-GCM. A Rust port uses the `aes-gcm` crate with the
  nonce and AAD of §4.3, with no streaming-AEAD crate needed. Note that age's construction differs: it has the final
  flag in the nonce, and ChaCha20-Poly1305.
- **`streamKey`.** HKDF-SHA256 with an *empty* salt. Some HKDF APIs treat a missing salt as `HashLen` zero bytes,
  which RFC 5869 makes equivalent. The vector pins it.
- **`headerAAD`.** It uses the same JSON rules as today's AAD (`SPEC.md` §12: `prekeyID` as `null`, standard base64),
  with `"streamedBodyCapable"` as the version string.
- **`streamedLength`.** A JSON number, and readers must not use `deny_unknown_fields`.
