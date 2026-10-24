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
