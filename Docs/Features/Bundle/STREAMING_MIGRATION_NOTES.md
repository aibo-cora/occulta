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
