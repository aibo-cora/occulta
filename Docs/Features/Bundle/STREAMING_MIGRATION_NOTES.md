# Streamed Bundle Bodies — Migration Notes per Stage

One note per stage of `STREAMING_SPEC.md` §12. Each says what stored or on-the-wire data the stage touches and
why nothing is lost. `STREAMING_SPEC.md` §13 is the summary.

## Stage 1 — received-attachment key, memory guard

**Stored data changed: none.**

- **Received attachments** are temporary (`tmp/`, deleted when the sheet closes). The key they are sealed under can
  now be the compose staging key where it used to be none. A file written before this stage is plaintext and is
  already removed by the sheet and by the launch-time sweep. Nothing reads an old file under the new key.
- **Writer and reader** both resolve through `ContactManager.receivedAttachmentKey(for:)`, so a message opened in
  this build is read under the key it was written with.
- **Memory guard:** refuses before a prekey is taken or a file written, so a refused bundle can be opened later on a
  build or device that can take it. Nothing is consumed. On the Simulator `os_proc_available_memory()` reports 0, so
  the guard treats the figure as unmeasurable there and refuses nothing. A device build has no such branch.
- **Wire format:** unchanged.

## Stage 2 — `BodyStream` codec, `WireHandle` split, interop vectors

**Stored data changed: none.** Nothing reads or writes a streamed bundle yet.

- **Inline bundles are byte-identical.** `WireHandle.encode(_:)` is now `encodeHeader` + the ciphertext +
  `encodeSections`, and `parse` is `parseHeader` + the ciphertext + `parseSections`. The existing interop vectors pass
  unchanged, and a test pins that the whole is the three parts joined.
- **Reader rules tighten, for inputs no build produces.** `parseHeader` accepts exactly `0x04` and `0x0A` and requires
  `min_reader_version` to equal `version`. Every bundle written since 1.8.2 has `0x04`/`0x04`, so none is refused that
  was readable. `0x05`–`0x09` stay marker-only. They were refused already, because `min_reader_version` exceeded
  `0x04`. Now the version check alone refuses them, so raising the accepted maximum to `0x0A` doesn't let them through.
- **`Version.streamedBodyCapable` exists, and is not yet a tier.** It has its wire byte (`0x0A`), the byte tables map
  it, and its raw value is in every chunk's AAD. It is deliberately not in `Version.known` and has no
  `minimumAppVersion`: `max(forAppVersion:)` can't return it, so no contact is recorded at it and no send chooses the
  streamed layout. Activation is stage 4 (§10). While it is outside `known`, `isAtLeast` is false for it against every
  tier, so a contact recorded at `0x0A` would read as the floor. Nothing records `0x0A` before stage 4, and none may.
- **`FileMeta.streamedLength`** is optional and omitted when nil, so an inline basket encodes as it did.
- **Interop vectors added, none changed:** `stream.key`, `stream.headerAAD.group`, `stream.nonce.*`, `stream.aad.*`,
  `stream.body.*`, `stream.manifest.*`, `basket.streamed.mixed` and `envelope.streamed.group`. The key, nonce, AAD and
  header AAD were checked against an independent computation (HKDF-SHA256 and the layouts by hand) as well as recorded.

## Stage 3 — I/O helpers, receive path, the four body consumers

**Stored data changed: none.** No build writes a streamed bundle until stage 4, so the new receive path is exercised
only by tests until then; the inline path is the one every real bundle takes.

- **The `.eatt` format is unchanged.** `Encryptor.write` (PR #132), `StreamingEncryptor`, `sealInPlace` and the
  import loops now go through `NoCacheFile`, and `Decryptor.range` is built on a new `forEachChunk`. The bytes are
  the same, and the existing `.eatt` tests pass unchanged. The writer is stricter than what it replaced: a file whose
  encryption fails, or whose `StreamingEncryptor` is dropped unfinished, is deleted, and `StreamingEncryptor` files
  now get `.complete` protection (they had the default). A draft's staged file is only ever finalised or abandoned
  by its owner, so none relies on a partial file surviving.
- **Inline bundles open as before.** `openGroup(bundle:ownerID:)` is a wrapper over the new
  `openGroup(bundle:body:ownerID:)`, which takes a `BundleBody`. The slot opener, the card slot opener and card
  recognition take an optional `body`, defaulting to `.inline(bundle)`. All inline tests pass unchanged.
- **The inbound file.** A streamed bundle is opened as a read handle and its copy in our container is unlinked as
  soon as the handle is open. The Secure Mode queue holds the handle in place of mapped bytes. Nothing of it is
  persisted: if the app is killed while it is queued, the unlinked file goes with the process. A bundle of any
  other layout is mapped as before, behind the memory guard.
- **Received messages** stay temporary: `StreamedReceive` deletes every file of a message when the sheet closes,
  when the session ends, and when pass 2 fails or is cancelled; the launch-time sweep covers a crash.
- **The tier is still not active.** `Version.streamedBodyCapable` is outside `known`, so no contact is recorded at
  it. `verifyConsistency` accepts the version, so a streamed bundle is not refused as an unknown one.
- **Two checks beyond the spec's wording**, both rejecting what the spec also rejects, only sooner: the manifest's
  streamed lengths are checked against the stream's *P* as soon as the manifest is decoded (§5.3 names the end of
  the stream), so a bundle whose lengths disagree is refused before any file is written; and `wrapRecipient` is
  internal rather than private, for the tests' sender.

## Stage 4 — send path, share session, tier activation

**Stored data changed: none that is read back.** What changes is what the app writes to `tmp/` and sends.

- **Tier activation.** `Version.streamedBodyCapable` is first in `Version.known`, keyed on 2.0.0. A contact is
  recorded at it from their first message from a 2.0.0 build; before that, and for any marker we can't read, they
  resolve below it and get the inline layout. Contacts already recorded keep their tier (`isAtLeast(.bodyDigestCapable)`
  is still true at the new one), and a byte above `0x0A` still reads as a newer build. **No build numbered 2.0.0 or
  later may ship with stages 3 and 4 missing**, and this branch changes no `MARKETING_VERSION` (still 1.11.1).
- **Which layout, decided once.** `ContactManager.encryptBundle`, `encryptGroupBundle` and `sendCardBundle` take a
  `BundleOutput`. Written to a file, a send is streamed when every recipient resolves to the tier, and inline
  otherwise. A card send is always streamed. An identity challenge or response in group format, and a shard-only
  bundle, take the layout a message to the same contact would, carrying a manifest and no files: a layout of their
  own would tell them apart. The memory guard (stage 1) now sits inside the inline branch, ahead of the first prekey
  taken, so it never meets a streamed send. The `Data`-returning forms remain for callers with nothing to stream.
- **Compose, drafts and the share sheet** pass the staged `.eatt` files through unread. A streamed send reads each
  one a chunk at a time; an inline send reads it whole once the guard allows. A draft's file is not touched by
  either, and is still removed by whoever removed it before.
- **Share sessions.** `ShareSession.staged` reads both formats. A session staged by the previous build (one AES-GCM
  blob per file, decrypted whole, as before) still sends, and still takes the streamed layout from memory when the
  recipient can read it. A session staged as `.eatt` stays on disk until it is sent. An image is read whole either
  way, because its EXIF is stripped and that needs the whole image. The introduction-card check reads both.
- **Wire compatibility.** A recipient on any build before this one is never sent `0x0A`: it is only chosen for a
  contact recorded at the tier, which only a 2.0.0 build can have caused.
- **Not done: the share extension's own staging.** See the stage 4 hand-over note. Until then the extension still
  stages one AES-GCM blob per file, capped at 100 MB, and the app reads them with the legacy reader above.
