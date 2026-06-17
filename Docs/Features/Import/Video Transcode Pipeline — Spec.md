# Video Transcode Pipeline — Spec

## Overview

Occulta currently imports videos at original quality using a zero-plaintext POSIX read loop. For large videos (2 GB+, 4K), playback in the message bubble triggers a 1.5 GB memory spike from AVFoundation's decode pipeline — inherent to decoding 4K frames regardless of `preferredForwardBufferDuration`.

This feature introduces a zero-plaintext transcode pipeline that generates a lower-resolution encrypted preview file alongside the original `.eatt`. It also lays the foundation for user-facing import quality settings where a user's chosen resolution becomes the import itself (no separate preview needed).

---

## Security Constraints (Non-Negotiable)

Same rules as all prior import work:

1. **No plaintext video data written to disk at any point.** `AVAssetExportSession` and `AVAssetWriter` both require a file URL output — both are ruled out. The transcode pipeline must operate entirely in memory.
2. **No forensic traces.** No temp files, no copies, no APFS journal artifacts.

---

## Architecture

### TranscodeSettings

All transcode operations — preview generation and quality-capped imports alike — are driven by a single parameterised struct:

```swift
struct TranscodeSettings {
    let resolution:    CGSize      // e.g. CGSize(width: 960, height: 540)
    let videoBitrate:  Int         // bits per second, e.g. 2_000_000
    let frameRateCap:  Double?     // nil = preserve original
    let codec:         CMVideoCodecType  // kCMVideoCodecType_H264 or HEVC
    let includeAudio:  Bool

    static let preview    = TranscodeSettings(resolution: CGSize(width: 960, height: 540),
                                              videoBitrate: 2_000_000,
                                              frameRateCap: 30,
                                              codec: kCMVideoCodecType_H264,
                                              includeAudio: true)
    static let hd1080     = TranscodeSettings(resolution: CGSize(width: 1920, height: 1080), ...)
    static let hd720      = TranscodeSettings(resolution: CGSize(width: 1280, height: 720),  ...)
    static let sd480      = TranscodeSettings(resolution: CGSize(width: 854,  height: 480),  ...)
}
```

The same pipeline code runs for all presets. The settings UI (future) just populates this struct.

---

## Import Branches

### Branch A — Original Quality (existing, unchanged)

User picks video → `requestAVAsset` → POSIX `open()` + `F_NOCACHE` + `F_RDAHEAD=0` → `StreamingEncryptor` → `main.eatt`

**After** `main.eatt` is written, automatically kick off Branch B with `TranscodeSettings.preview` to produce `main_preview.eatt`.

### Branch B — Transcoded (new, used for both preview generation and future quality settings)

User picks video → transcode pipeline → `main.eatt` at chosen resolution.

When the user selects a quality preset other than Original, Branch B produces the only `.eatt` — no preview file is needed because the import itself is already small enough to play directly in the bubble.

```
[AVURLAsset URL from requestAVAsset]
        │
        ▼
[AVAssetReader]
   ├─ AVAssetReaderVideoCompositionOutput
   │    renderSize: settings.resolution         → CVPixelBuffer (memory)
   │         │
   │         ▼
   │    VTCompressionSession (H.264/HEVC)       → CMSampleBuffer (memory)
   │         │
   └─ AVAssetReaderTrackOutput (audio)          → CMSampleBuffer (memory, passthrough AAC)
        │
        ▼
[In-Memory fMP4 Muxer]
   Assembles ftyp + moov + repeating (moof + mdat) pairs
   Interleaves video and audio fragments
        │
        ▼
[StreamingEncryptor]                            → .eatt written to disk
```

---

## fMP4 Muxer (The Hard Part)

`AVAssetWriter` is ruled out (requires seekable file output). The muxer is implemented from scratch.

**Output format: Fragmented MP4 (ISO 14496-12)**

Fragmented MP4 requires no seeking — the `moov` box declares track parameters only, with no sample table. Samples live in self-contained `moof` + `mdat` fragment pairs. This is what HLS uses and what AVFoundation handles natively.

**Box structure:**

```
ftyp  — file type declaration (mp42 / iso5)
moov
  mvhd  — movie header
  trak (video)
    tkhd
    mdia
      mdhd
      hdlr (vide)
      minf
        vmhd
        dinf → dref
        stbl  — empty (no samples; all in moof/mdat)
          stsd → avc1/hvc1 with SPS/PPS from VTCompressionSession format description
          stts, stsc, stsz, stco (all zero-entry)
  trak (audio, if includeAudio)
    — same structure, stsd → mp4a
  mvex
    trex (video)
    trex (audio)

[repeating per keyframe group:]
moof
  mfhd  — sequence number
  traf (video)
    tfhd
    tfdt  — decode time
    trun  — sample table (offsets, durations, sizes, flags)
  traf (audio, interleaved)
    tfhd
    tfdt
    trun
mdat  — raw encoded bytes (video NAL units + audio AAC frames)
```

**Key implementation details:**

- SPS and PPS for H.264 are extracted from `VTCompressionSession`'s output `CMFormatDescription` on the first keyframe sample. They go into the `avc1` box's `avcC` record.
- Decode timestamps vs. presentation timestamps: `VTCompressionSession` may reorder frames (B-frames). `CMSampleBuffer` carries both DTS and PTS. `trun` entries carry composition time offsets (`ctts`) when PTS ≠ DTS.
- Fragment boundary: start a new `moof`/`mdat` pair on each keyframe (IDR). This is the natural HLS segment boundary and gives AVFoundation clean seek points.
- Audio fragmentation: emit audio fragments at the same boundaries as video. AAC frames from `AVAssetReaderTrackOutput` are packed into the same `mdat` as the corresponding video fragment.
- All multi-byte integers in MP4 boxes are big-endian.

Estimated scope: 350–450 lines of careful box serialization, plus unit tests against known-good fMP4 files parsed by `mp4info` or similar.

---

## File Naming Convention

| Scenario | Files |
|---|---|
| Original quality import | `media_XXXXXXXX.eatt` (4K) + `media_XXXXXXXX_preview.eatt` (960p) |
| 1080p quality import | `media_XXXXXXXX.eatt` (1080p only — IS the preview) |
| 720p / 480p import | `media_XXXXXXXX.eatt` (at chosen res — IS the preview) |

---

## Playback Selection Logic

On both compose and read sides:

1. Check for `[name]_preview.eatt`. If present, use it for the bubble player.
2. Otherwise use `[name].eatt` directly (already at a playable resolution).

The resource loader (`AVAssetResourceLoaderDelegate`) is unchanged — it decrypts `.eatt` chunk-by-chunk regardless of which file is targeted.

---

## Read Side (Recipient)

The bundle contains only `main.eatt` (original quality). On first open:

- If `main.eatt` is above a resolution/size threshold, run Branch B with `TranscodeSettings.preview` to generate `[name]_preview.eatt` locally.
- Preview generation runs once in the background after the bundle is decrypted and stored. The bubble shows the thumbnail until preview generation completes (same pending bubble pattern used for import).

The recipient generates their own preview — the bundle stays the same size.

---

## Future: User-Facing Import Settings

The settings UI (a sheet presented before import begins, or in app settings as a default) populates `TranscodeSettings` and passes it into `handleMedia`. No pipeline changes required.

Proposed presets:
- **Original** — POSIX path, no transcode, preview generated automatically
- **1080p HD** — Branch B, ~200–400 MB for a 2 GB source
- **720p** — Branch B, ~80–150 MB
- **480p** — Branch B, ~30–60 MB

The `TranscodeSettings` static presets defined now become the menu options later.

---

## Expected Memory Impact

| Scenario | Current | After |
|---|---|---|
| Import (original quality) | ~90 MB flat | ~90 MB flat + preview transcode peak (~200 MB briefly) |
| Bubble playback (4K source) | ~1.5 GB | ~30–50 MB (playing 960p preview) |
| Bubble playback (1080p import) | ~1.5 GB | ~150–250 MB |
| Bubble playback (720p import) | ~1.5 GB | ~60–100 MB |

---

## Implementation Order

1. **`TranscodeSettings` struct** — define presets, no pipeline yet
2. **fMP4 muxer** — standalone unit, testable in isolation with a known H.264 bitstream
3. **Transcode pipeline** — `AVAssetReader` + `VTCompressionSession` + audio passthrough → muxer → `StreamingEncryptor`
4. **Preview generation** — wire into `handleMedia` after original import completes; name as `_preview.eatt`
5. **Playback selection** — update resource loader call site to prefer preview file
6. **Read-side preview generation** — trigger after bundle open if source exceeds threshold
7. **Import settings UI** — sheet + persistence; use `TranscodeSettings` presets

Steps 1–5 are the core of this feature. Steps 6–7 are independent follow-ons.

---

## Open Questions

- **Codec for preview:** H.264 is safer for compatibility; HEVC saves ~40% size at same quality. iPhone 11 hardware-encodes both. Recommend H.264 for preview, HEVC as optional setting.
- **Frame rate cap:** Cap preview at 30fps to reduce encoded frame count. Original quality branch preserves source frame rate.
- **Portrait/square videos:** `renderSize` must respect source aspect ratio. Compute `renderSize` from the asset's natural size, fitting within the target resolution box.
- **HDR:** Source 4K video may be HDR (HLG/PQ). Downsampling to SDR for preview is fine; the preview is for a 260×200 bubble.
