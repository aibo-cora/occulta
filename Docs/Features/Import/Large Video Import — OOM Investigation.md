# Large Video Import — OOM Investigation

## Background

Occulta imports media from the user's Photos library and encrypts it into the `.eatt` chunked format before storing it in the app sandbox. For small files this is trivial. For large videos (~2 GB) the app was crashing with a foreground OOM (Jetsam termination) on every attempt.

This document records the full investigation: what was tried, why each approach failed, what finally worked, and the security constraints that shaped every decision.

---

## Security Constraints (Non-Negotiable)

Every approach was evaluated against two hard rules:

1. **No plaintext files in the app sandbox.** Writing a decrypted copy of the video to a temp file — even briefly — is a forensic trace. A sophisticated analysis of the device could recover the plaintext from deleted temp files, the filesystem journal, or the unified buffer cache. This ruled out `loadFileRepresentation`, `loadTransferable(type: URL.self)`, and `PHAssetResourceManager.writeData(for:toFile:)`.

2. **No unnecessary evidence of concealment.** The app should not leave artifacts that indicate something was hidden or deleted. Traces of large temp files appearing and disappearing are suspicious.

These constraints meant the only acceptable path was to read source bytes directly into an encryption loop — never materialising the plaintext anywhere on disk.

---

## The Encryption Format

Videos are stored as `.eatt` files (chunked AES-GCM):

- **101-byte header**: magic, version, chunk size, chunk count, plaintext size, base nonce, key salt, HMAC-SHA256 header MAC
- **256 KB chunks**, each independently encrypted with AES-GCM (16-byte tag appended)
- **Per-file HKDF key** derived from the contact's symmetric key and a random salt
- **Derived nonces** per chunk (base nonce XOR chunk index)

`StreamingEncryptor` writes chunks as they arrive via `append()`, holding at most one 256 KB buffer in memory at a time. `finalize()` flushes the last partial chunk and writes the authenticated header. `F_NOCACHE` is set on the write `FileHandle` so encrypted chunks bypass the kernel's unified buffer cache on the way to disk.

---

## iOS Memory Model — Why 2 GB Is Hard

- **No swap space.** iOS never pages anonymous memory to disk. Every byte allocated must fit in physical RAM.
- **Jetsam.** The foreground app limit on an iPhone 11 (4 GB device) is approximately 1.5–2 GB. The kernel kills the app instantly when this is exceeded — no warning, no recovery.
- **Unified buffer cache (UBC).** Every file read goes through the UBC by default. Sequential reads of a 2 GB file fill 2 GB of buffer cache. The kernel counts this against Jetsam limits even though it is technically evictable.
- **`MADV_DONTNEED` is advisory on Darwin.** Unlike Linux (where it is immediate and guaranteed), on Darwin the kernel may ignore or defer it, particularly for `MAP_SHARED` file-backed mappings. It cannot be relied upon to bound physical memory.
- **`mmap` virtual ≠ physical, but fault rate matters.** A 2 GB `mmap` region does not immediately consume 2 GB of RAM — pages are faulted in on access. However, if pages are faulted in faster than the eviction thread can reclaim them, Jetsam terminates the app.

---

## Approaches Tried

### 1. `PHAssetResourceManager.requestData` — basic

**What:** Request the video bytes via the Photos framework streaming API. Process each delivered `Data` in the `dataReceivedHandler`.

**Result:** Crashed. Despite documentation implying ~1 MB deliveries, for a 1.96 GB video the handler was called with a single ~1.5 GB `Data`, then a second delivery pushed total memory to ~2.9 GB.

**Why it failed:** `PHAssetResourceManager` delivers data in arbitrarily large chunks — apparently sized to the underlying file segment, not a fixed small unit. There is no way to control delivery chunk size.

### 2. `PHAssetResourceManager.requestData` + `MADV_DONTNEED` on delivered chunks

**What:** Same as above, but walk each delivered `Data` in 64 KB slices inside `withUnsafeBytes`, calling `madvise(MADV_DONTNEED)` after each slice.

**Result:** Memory warning and crash. The delivered `Data` is heap-backed (a `malloc` allocation), not `mmap`-backed. `madvise` on heap memory is a no-op.

### 3. `requestAVAsset` (.highQualityFormat) → URL → file read

**What:** Use `PHImageManager.requestAVAsset` to obtain a local file URL, then read from it.

**Result:** Crashed before reading started. The `.highQualityFormat` delivery mode transcode HEVC → H.264 in memory.

### 4. `requestAVAsset` (.automatic) → URL → `mmap` + `MADV_DONTNEED`

**What:** Use `.automatic` delivery (no transcoding), `mmap` the source file, read in 64 KB slices, call `MADV_DONTNEED` after each.

**Result:** Stuck on "Loading…" then spiked to ~3 GB. `MADV_SEQUENTIAL` was set at the time, instructing the kernel to aggressively prefetch the entire file. Also suspected: AVFoundation background analysis running in parallel with our reads.

After removing `MADV_SEQUENTIAL` and the `phThumbnail` call (which loaded photo metadata), the spike persisted. `MADV_DONTNEED` is not reliable on Darwin.

### 5. `requestAVAsset` → URL → `Darwin.read()` in 64 KB chunks

**What:** Swap `mmap` for raw POSIX `read()` syscalls.

**Result:** Crashed. `F_NOCACHE` was applied to the *write* `FileHandle` (inside `StreamingEncryptor`) but **not** to the *source* file descriptor. Every `read()` call filled the kernel buffer cache. For 2 GB of sequential reads, 2 GB of buffer cache accumulated, pushing the process over the Jetsam limit.

### 6. `loadInPlaceFileRepresentation`

**What:** Attempt to get a file-system URL for the Photos asset without copying it, avoiding full Photos library authorization.

**Result:** Photos returned: *"loadInPlaceFileRepresentationForTypeIdentifier is not supported. Use loadFileRepresentationForTypeIdentifier instead."*

### 7. `loadFileRepresentation` / `loadTransferable(type: URL.self)`

**What:** Let the system write the video to a temp file and provide us a URL.

**Result:** Rejected on security grounds. Both create a plaintext copy of the video in the app's temp directory — a forensic trace. Ruled out regardless of memory behaviour.

### 8. `NSItemProvider.loadDataRepresentation` + `MADV_DONTNEED`

**What:** Load the video data via the picker's `NSItemProvider`, walk it in 64 KB slices with `madvise(MADV_DONTNEED)`.

**Advantage:** Requires no Photos library authorization — the picker's implicit grant is sufficient, so no permission dialog is shown.

**Result:** Not fully stress-tested at 2 GB before the investigation pivoted. The fundamental uncertainty: is the delivered `Data` `mmap`-backed or heap-backed? If heap-backed, `MADV_DONTNEED` is a no-op and the approach collapses the same way as PHAssetResourceManager. Retained as a fallback path for cases where Photos authorization is unavailable.

---

## What Finally Worked

### Primary Path: `requestAVAsset` → POSIX read with `F_NOCACHE` + `F_RDAHEAD=0`

**Key insight:** The chunked read loop itself was never the problem. The problem was *buffer cache accumulation on the read side*, which we had never addressed.

**Implementation:**

```swift
// 1. Get the local file URL (requires Photos authorization)
PHImageManager.default().requestAVAsset(forVideo: asset, options: opts) { avAsset, _, info in
    // ua.url points to the video file in the Photos library
}

// 2. Open with POSIX open() for direct fd control
let fd = open(videoURL.path(percentEncoded: false), O_RDONLY)

// 3. Bypass the unified buffer cache on reads
fcntl(fd, F_NOCACHE, 1)

// 4. Disable kernel readahead — prevents speculative prefetch of the whole file
//    NOTE: pass int 0 directly, NOT &someVar (pointer would be interpreted as a
//    large non-zero integer on 64-bit, silently leaving readahead enabled)
fcntl(fd, F_RDAHEAD, 0)

// 5. Page-aligned buffer for optimal direct I/O
var rawBuf: UnsafeMutableRawPointer? = nil
posix_memalign(&rawBuf, Int(sysconf(_SC_PAGESIZE)), 65_536)

// 6. Read loop — RSS stays flat throughout
while true {
    let n = read(fd, buf, 65_536)
    if n == 0 { break }
    // Data(bytesNoCopy:) — no heap copy; encryptor.append() copies into its
    // 256 KB buffer, which is the only copy made
    try encryptor.append(Data(bytesNoCopy: buf, count: n, deallocator: .none))
}
try encryptor.finalize()
```

**Observed behaviour:** Memory held flat at ~90 MB before, during, and throughout the entire 2 GB import. The POSIX + `F_NOCACHE` + `F_RDAHEAD=0` combination prevented any buffer cache accumulation.

**Authorization:** This path requires `PHPhotoLibrary.requestAuthorization`. The permission dialog is shown once; subsequent imports reuse the existing grant.

**`F_RDAHEAD` bug to avoid:** A widely circulated code sample passes `&readAhead` (a pointer) as the third argument to `fcntl(fd, F_RDAHEAD, ...)`. On a 64-bit device, this passes the *address* of the variable — a large non-zero integer — which the kernel interprets as "readahead = on", silently doing the opposite of what was intended. Always pass the integer literal `0` directly.

---

## The Post-Import Spike (Second Crash)

After fixing the import loop, a new crash pattern appeared: memory held flat at ~90 MB for the entire 15-second import, then spiked immediately to 900 MB → 1.5 GB → 2.5 GB the moment the import finished.

**Root cause:** `MessageBubble` was creating an `AVPlayer` inside `onAppear`. The moment the encrypted video was added to `messages` and the bubble appeared on screen, AVFoundation initialised and immediately invoked the `AVAssetResourceLoaderDelegate` to understand the video's container structure (moov atom, key frames, buffer-ahead). The resource loader's `while cursor < end` decryption loop had no `autoreleasepool`, so every `AES.GCM.SealedBox`, intermediate `Data`, and CryptoKit allocation accumulated for the entire duration of AVFoundation's initialisation request — easily hundreds of MB for a 2 GB video.

**Fixes:**

1. **Lazy player creation.** Moved `AVPlayer` initialisation from `onAppear` to an explicit tap gesture. The video bubble shows a static play button overlay until the user taps. The resource loader never runs at import time.

2. **`autoreleasepool` in the resource loader loop.** Each call to `decryptChunk` now executes inside an `autoreleasepool` block, ensuring intermediate allocations are freed before the next chunk is decrypted. Peak memory per playback chunk is bounded to a few MB.

3. **`F_NOCACHE` on the resource loader's `FileHandle`.** Decryption reads from the encrypted `.eatt` file no longer accumulate in the buffer cache during playback.

---

## Architecture Summary

```
PHPickerViewController
    │
    ├─ assetIdentifier present + Photos authorized
    │       │
    │       ├─ PHImageManager.requestAVAsset(.automatic)
    │       │       → local file URL
    │       │
    │       └─ POSIX open() + F_NOCACHE + F_RDAHEAD=0
    │               → read() 64 KB loop
    │               → StreamingEncryptor.append()   [256 KB chunks, F_NOCACHE write]
    │               → StreamingEncryptor.finalize() [authenticated header]
    │               → .eatt file in app sandbox
    │
    └─ no assetIdentifier (fallback)
            │
            └─ NSItemProvider.loadDataRepresentation
                    → MADV_DONTNEED on delivered Data (if mmap-backed)
                    → same StreamingEncryptor path

Playback:
    MessageBubble (tap to play)
        → AVPlayer + AVAssetResourceLoaderDelegate
        → decryptChunk() per AVFoundation request
            [F_NOCACHE on read handle, autoreleasepool per chunk]
```

---

## Rejected Approaches and Why

| Approach | Reason Rejected |
|---|---|
| `loadFileRepresentation` | Plaintext file in sandbox — forensic trace |
| `loadTransferable(type: URL.self)` | Plaintext temp file — forensic trace |
| `PHAssetResourceManager.writeData(for:toFile:)` | Plaintext file in sandbox — forensic trace |
| `mmap` + `MADV_DONTNEED` | `MADV_DONTNEED` is advisory on Darwin; unreliable for bounded physical memory |
| `loadInPlaceFileRepresentation` | Not supported by Photos for video assets |
| `read()` without `F_NOCACHE` on source fd | Buffer cache accumulates full file in RAM |

---

## Key Lessons

- **`F_NOCACHE` must be applied to both sides.** Writes were protected from the start (`StreamingEncryptor`). Reads were not, which was the primary crash cause for two months.
- **`F_RDAHEAD=0` is a direct int, not a pointer.** A subtle API misuse silently re-enables the feature you are trying to disable.
- **`MADV_DONTNEED` is not a substitute for `F_NOCACHE` on Darwin.** It is advisory, unreliable for `MAP_SHARED` mappings, and a no-op for heap-backed `Data`.
- **Eager `AVPlayer` initialisation is a hidden memory cost.** AVFoundation's startup I/O for a 2 GB video is itself an OOM risk. Never create a player until the user requests playback.
- **`autoreleasepool` in AES-GCM loops is not optional.** CryptoKit and `Data` operations produce many short-lived allocations. Without a per-iteration pool, these accumulate for the duration of the entire decryption pass.
- **Flat memory during import does not mean success.** The first version of the POSIX fix showed a perfect flat line for 15 seconds, then crashed immediately after. The crash was in unrelated code that ran post-import. Profile the full lifecycle, not just the loop.
