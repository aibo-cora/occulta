# Share Extension — Detailed Architecture Plan

---

## Step 1: App Group Container

Create the App Group `group.com.occulta.shared`. Add the entitlement to both the main app target and the share extension target.

The shared container has this structure:

```
group.com.occulta.shared/
├── ShareIndex.sqlite              # Shared SwiftData store (encrypted fields)
├── ShareIndex.sqlite-wal
├── ShareIndex.sqlite-shm
└── pending/
    └── <session-uuid>/            # One directory per share session
        ├── manifest.enc           # AES-GCM encrypted manifest
        ├── 0.tmp                  # Copied file (opaque name)
        ├── 1.tmp                  # Copied file (opaque name)
        └── ...
```

The `pending/` directory uses `.completeFileProtection`. **Every file written into the shared container must have `.completeFileProtection` set explicitly after creation.** `FileManager.copyItem` preserves the *source* file's protection class, not the destination directory's. Directory-level protection is not inherited by copied files. See Step 7 for the per-file protection call.

---

## Step 2: Shared SE Key

### Creation

Create a new P-256 key in the Secure Enclave at first launch, with the access group set from creation:

```
Tag:            "share.index.se.key.occulta"
Key type:       P-256 (kSecAttrKeyTypeECSECPrimeRandom)
Protection:     Secure Enclave (kSecAttrTokenIDSecureEnclave)
Access control: kSecAttrAccessibleWhenUnlockedThisDeviceOnly + .privateKeyUsage
Access group:   "group.com.occulta.shared"   ← set at creation, not migrated
Permanent:      true
```

The test proved that creating a new SE key with an access group works. This key is never migrated — it is born in the shared group.

### Key Derivation

Derive a symmetric key for encrypting the contact index, using the same pattern as the local DB key:

```
ECDH(shareIndexSEKey, G)  →  32 bytes raw shared secret

HKDF<SHA256>(
  IKM:    raw ECDH secret (32 bytes)
  Salt:   shareIndexSEKey public key x963 (65 bytes)
  Info:   "Occulta-v1-share-index-2026"
  Output: 32 bytes → SymmetricKey (AES-256)
)
```

New domain separator — never reuses an existing info string. The derivation is deterministic: both the main app and the extension derive the same symmetric key because they share access to the same SE private key via the access group.

### Where This Lives

Add a new manager class: `ShareIndexKeyManager`. It handles:
- Creating the SE key if absent (first launch after update)
- Retrieving the SE key reference
- Deriving the symmetric key via ECDH(privKey, G) → HKDF
- Encrypting/decrypting Data blobs for the index

Both the main app and the extension link this class. It is the only crypto code the extension needs. It never touches the identity key, the local DB key, prekeys, or ML-KEM material.

### Why Not Reuse the Local DB Key

The local DB key is derived from the identity SE key + a random Keychain component. Neither is in the shared access group, and migrating them failed. The share index key is a separate, purpose-scoped key with its own domain separator. Compromise of this key reveals only contact display names and identifiers — not key material, not messages, not prekey state.

---

## Step 3: SwiftData Model — `ShareableContact`

### Schema

```swift
@Model
final class ShareableContact {
    /// AES-GCM encrypted contact identifier (the hash-based ID from Contact.Profile).
    var encryptedIdentifier: Data = Data()
    /// AES-GCM encrypted display name (givenName + " " + familyName, assembled before encryption).
    var encryptedDisplayName: Data = Data()

    init(encryptedIdentifier: Data, encryptedDisplayName: Data) {
        self.encryptedIdentifier = encryptedIdentifier
        self.encryptedDisplayName = encryptedDisplayName
    }
}
```

Both fields are AES-GCM encrypted with the share index key before storage. No plaintext contact data ever touches the shared SwiftData store. The identifier is encrypted because it is derived from the public key hash and constitutes relationship metadata.

### Store Location

The `ModelContainer` for this model points to the shared App Group container:

```swift
let sharedURL = FileManager.default
    .containerURL(forSecurityApplicationGroupIdentifier: "group.com.occulta.shared")!
    .appendingPathComponent("ShareIndex.sqlite")

let config = ModelConfiguration(
    schema: Schema([ShareableContact.self]),
    url: sharedURL,
    cloudKitDatabase: .none
)
```

The main app creates a second `ModelContainer` for this store (separate from its primary contact database). The extension creates its own `ModelContainer` pointing to the same file.

### SQLite File Protection

The `ShareIndex.sqlite` file (and its `-wal` and `-shm` companions) must have `.completeFileProtection` set explicitly. Even though all fields are AES-GCM encrypted, the SQLite metadata leaks contact count, row sizes, and last-modified timestamps — this is relationship metadata. Set protection on first creation and re-apply after every `syncShareIndex` call (SQLite may recreate companion files during checkpointing):

```swift
for suffix in ["", "-wal", "-shm"] {
    let fileURL = sharedURL.appendingPathExtension(suffix.isEmpty ? "" : String(suffix.dropFirst()))
    // Construct actual URLs for .sqlite, .sqlite-wal, .sqlite-shm
    if FileManager.default.fileExists(atPath: fileURL.path) {
        try (fileURL as NSURL).setResourceValue(
            URLFileProtection.complete,
            forKey: .fileProtectionKey
        )
    }
}
```

### Cross-Process Safety

SQLite in WAL mode (SwiftData's default) supports concurrent readers. The main app is the only writer. The extension only reads. This is safe without additional coordination because:

- SQLite WAL allows multiple concurrent readers alongside a single writer
- The extension opens the store, reads all records, and closes — it does not hold long-lived transactions
- The main app writes synchronously during contact mutations and calls `modelContext.save()` before returning

If the extension happens to read while the main app is mid-write, it sees the pre-write state (snapshot isolation). This is acceptable — the contact list will be current on the next share invocation.

---

## Step 4: Sync Mechanism

### When to Sync

The main app rebuilds the shared index after any mutation to the contact list:

1. **Contact added** — after `ContactManager.save(contact:)` completes and the main `modelContext.save()` succeeds
2. **Contact deleted** — after the delete + `modelContext.save()`
3. **Contact renamed** — after the name fields are re-encrypted and saved
4. **App launch** — full reconciliation on every `scenePhase == .active`, as a safety net for missed syncs (app killed during mutation, etc.)

### How to Sync — Full Rebuild

The index is small (just identifier + display name per contact). A full rebuild on every mutation is cheap and eliminates incremental sync bugs:

```
1. Fetch all Contact.Profile records from the main store
2. For each record:
   a. Decrypt the identifier (already plaintext in the main store)
   b. Decrypt givenName and familyName using the local DB crypto manager
   c. Assemble displayName = "\(givenName) \(familyName)".trimmingCharacters(in: .whitespaces)
   d. Re-encrypt identifier and displayName using the share index key
   e. Create a ShareableContact with the encrypted fields
3. Open the shared ModelContainer
4. Delete all existing ShareableContact records
5. Insert the new records
6. Save
7. Re-apply .completeFileProtection on ShareIndex.sqlite, .sqlite-wal, .sqlite-shm
   (SQLite may recreate companion files during checkpointing)
```

The delete-all-then-insert pattern is atomic from SwiftData's perspective (single `save()` call). If the app is killed between delete and insert, the next launch reconciliation rebuilds from scratch.

### What This Function Looks Like

A single method on `ContactManager`:

```swift
func syncShareIndex() throws
```

Called after every contact mutation and on `scenePhase == .active`. No async — the dataset is small and the UI is not blocked because the main contact save already completed.

### What the Extension Never Does

The extension never writes to the shared SwiftData store. It opens a read-only `ModelContainer`, fetches all `ShareableContact` records, decrypts them in memory for display, and closes the store.

---

## Step 5: Extension Target

### Xcode Setup

Add a Share Extension target. Configure `Info.plist`:

```xml
<key>NSExtension</key>
<dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.share-services</string>
    <key>NSExtensionPrincipalClass</key>
    <string>$(PRODUCT_MODULE_NAME).ShareViewController</string>
    <key>NSExtensionActivationRule</key>
    <dict>
        <key>NSExtensionActivationSupportsFileWithMaxCount</key>
        <integer>20</integer>
        <key>NSExtensionActivationSupportsImageWithMaxCount</key>
        <integer>20</integer>
    </dict>
</dict>
```

Predicate-based activation rule — not `TRUEPREDICATE`. App Review rejects `TRUEPREDICATE`.

### What the Extension Links

Shared framework or source files:
- `ShareableContact` (SwiftData model)
- `ShareIndexKeyManager` (SE key + HKDF + AES-GCM for the index)

The extension does NOT link:
- `Manager.Key` (identity key, local DB key)
- `Manager.Crypto` (main app encryption)
- `ContactManager` (SwiftData CRUD on the main store)
- `PrekeyManager`, `PQProvider`, `OccultaBundle`, `ForwardSecrecy`

---

## Step 6: Extension UI Flow

### Phase 1 — Contact Picker

1. Extension launches via the share sheet.
2. Open the shared `ModelContainer` (read-only).
3. Fetch all `ShareableContact` records.
4. Derive the share index symmetric key from the shared SE key.
5. Decrypt each record's `encryptedIdentifier` and `encryptedDisplayName` in memory.
6. Display a scrollable list of contact names.
7. User taps a contact.
8. **Immediately after selection:** zero the decrypted contact list. Overwrite every decrypted `Data` buffer with `withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }`, then release. For `String` values, reassign to `""` (this does not guarantee zeroing of the original heap allocation, but it releases the reference; Swift's small-string optimization stores short names inline on the stack, which is reclaimed on scope exit). Retain only the selected contact's identifier (needed for the manifest).

If the shared store is empty (no contacts yet, or first launch before sync), show a message: "Open Occulta to set up your contacts."

### Phase 2 — File Intake (see Step 7 for details)

After contact selection, copy all attachments to the shared container.

### Phase 3 — Handoff

Write the encrypted manifest. Open the main app via URL scheme. Call `completeRequest`.

---

## Step 7: File Handling — Large Files

This is where the memory ceiling matters. The extension has ~120 MB. A single 4K video can be several GB.

### The Rule

**Never load file content into memory in the extension.** Every file operation is a filesystem-level copy — the bytes flow from source to destination through the kernel, not through app memory.

### Receiving Attachments

Each `NSExtensionItem` contains an array of `NSItemProvider` attachments. For each attachment:

```swift
let provider: NSItemProvider = ...

// loadFileRepresentation writes a temp copy to the extension's tmp directory
// and gives us a URL. The file data never enters our memory.
provider.loadFileRepresentation(forTypeIdentifier: UTType.data.identifier) { url, error in
    guard let sourceURL = url else { return }
    // sourceURL is valid only inside this closure.
    // Copy immediately — see below.
}
```

`loadFileRepresentation` is the correct API. It gives a file URL to a temp copy that the OS manages. The alternative — `loadDataRepresentation` — loads the entire file into a `Data` object and will crash on large files. Never use it.

### Copying to the Shared Container

Create a session directory with a UUID to isolate concurrent share sessions:

```swift
let sessionID = UUID().uuidString
let sessionDir = sharedContainerURL
    .appendingPathComponent("pending")
    .appendingPathComponent(sessionID)

try FileManager.default.createDirectory(at: sessionDir, withIntermediateDirectories: true)

// Set file protection on the session directory
try (sessionDir as NSURL).setResourceValue(
    URLFileProtection.complete,
    forKey: .fileProtectionKey
)
```

For each attachment, copy via `FileManager.copyItem` and **immediately set file protection**:

```swift
let destinationURL = sessionDir.appendingPathComponent("\(index).tmp")
try FileManager.default.copyItem(at: sourceURL, to: destinationURL)

// CRITICAL: copyItem preserves the SOURCE file's protection class, not the
// destination directory's. The source is the extension's tmp/ directory, which
// typically uses .completeUntilFirstUserAuthentication or weaker. Without this
// explicit call, plaintext files are readable when the device is locked.
try (destinationURL as NSURL).setResourceValue(
    URLFileProtection.complete,
    forKey: .fileProtectionKey
)
```

`FileManager.copyItem` on APFS performs a copy-on-write clone — it is O(1) in time and space for files on the same volume. No memory pressure regardless of file size. For files across volumes (rare on iOS — everything is on the same APFS volume), it falls back to a kernel-level byte copy that streams through a small buffer, still without loading the file into app memory. The `setResourceValue` call after the copy is a metadata-only operation — it does not re-read the file.

### File Naming

Files are named `0.tmp`, `1.tmp`, `2.tmp`, etc. Original filenames are recorded only in the manifest (encrypted). This prevents filename metadata from leaking via filesystem inspection of the shared container.

### UTI Tracking

The manifest records each file's UTI (Uniform Type Identifier) so the main app knows how to handle it — specifically, which files are images that need EXIF stripping. The UTI comes from `NSItemProvider.registeredTypeIdentifiers` and is stored in the manifest before encryption.

### What If `loadFileRepresentation` Fails

Some `NSItemProvider` sources (e.g., certain apps sharing via `UIActivityItemSource`) may not support file representation. For these, `loadDataRepresentation` is the only option. If the data is small (< 10 MB), load it and write to the session directory. If it is large, present an error: "This file is too large to share from this app. Open Occulta to encrypt it directly."

Check `provider.registeredTypeIdentifiers` and attempt `loadFileRepresentation` first. Fall back to `loadDataRepresentation` only if file representation is unavailable, and only with a size guard. When writing `Data` to disk via `Data.write(to:options:)`, use `.completeFileProtection` in the options, or set the protection attribute explicitly after writing — the same rule as `copyItem` applies.

### Sequential Processing

Process attachments one at a time, not concurrently. This ensures:
- At most one temp file from `loadFileRepresentation` exists at a time (the OS may reclaim them after the closure returns)
- The copy completes before the next attachment is requested
- No risk of exceeding memory from multiple concurrent `loadDataRepresentation` fallbacks

Use a serial async queue or process with `for await` in a `TaskGroup` with max concurrency of 1.

---

## Step 8: Manifest

The manifest tells the main app what was selected and where the files are. It contains:

```swift
struct ShareManifest: Codable {
    /// The contact identifier (decrypted by the extension during picker,
    /// re-encrypted here for transport).
    let contactIdentifier: String
    /// One entry per file, in order.
    let files: [FileEntry]
    /// Timestamp for stale session detection.
    let createdAt: Date

    struct FileEntry: Codable {
        /// Filename in the session directory ("0.tmp", "1.tmp", ...)
        let filename: String
        /// UTI of the original content (e.g., "public.jpeg", "com.adobe.pdf")
        let uti: String
        /// Original file extension (e.g., "jpg", "pdf") — needed for
        /// constructing the Occulta.File.Metadata after encryption.
        let fileExtension: String
    }
}
```

### Encryption

The manifest is JSON-encoded, then AES-GCM encrypted with the share index key, and written to `manifest.enc` in the session directory. After writing, set `.completeFileProtection` explicitly on the file — the same `copyItem` inheritance caveat applies to any file created in the shared container. The contact identifier inside is plaintext within the encrypted blob — it never touches disk unencrypted.

### Why Encrypt the Manifest

The manifest contains the contact identifier, which links to a real person. Even though the shared container is protected by iOS file protection, defense in depth requires that relationship metadata is application-layer encrypted. An attacker who somehow accesses the container while the device is unlocked (e.g., via a jailbreak tool running in the background) sees only encrypted blobs.

---

## Step 9: Handoff to Main App

After writing all files and the manifest:

1. Extension calls `completeRequest(returningItems: nil)` — this dismisses the extension UI.
2. Extension opens the main app via a registered URL scheme:

```
occulta://share?session=<session-uuid>
```

The session UUID is the only parameter. It is not sensitive — it's a random UUID that maps to a directory name. The manifest inside that directory (encrypted) contains all the sensitive data.

### URL Scheme Registration

Register `occulta://` in the main app's `Info.plist` as a custom URL scheme. The main app handles it in `onOpenURL`.

### What If the Main App Doesn't Launch

The user might cancel, the app might not be installed (shouldn't happen — the extension comes from the same app), or the system might kill it. The files remain in the `pending/` directory until the next cleanup sweep (Step 12).

---

## Step 10: Main App Processing

When the main app opens via `occulta://share?session=<uuid>`:

### 10a. Read and Decrypt the Manifest

1. Construct the session directory path from the UUID.
2. Read `manifest.enc`.
3. Derive the share index key (same SE key, same HKDF).
4. Decrypt the manifest.
5. Parse the `ShareManifest`.

### 10b. Identify the Contact

1. Use `manifest.contactIdentifier` to look up the `Contact.Profile` in the main SwiftData store.
2. Retrieve the contact's public key material (decrypt from the contact record).
3. If the contact is not found (deleted between share and processing), show an error and clean up.

### 10c. EXIF Stripping (Images Only)

For each file in the manifest where `uti` conforms to `public.image`:

1. Read the file from the session directory into a `CGImageSource`.
2. Create a `CGImageDestination` writing to a new temp file.
3. Copy the image data with an empty metadata properties dictionary — this strips all EXIF, GPS, camera model, lens info, timestamps, and thumbnail previews.
4. Replace the original file in the session directory with the stripped version.
5. Delete the original.

For non-image files: no stripping. They are treated as opaque blobs.

This happens in the main app, not the extension. The main app has no memory ceiling and can handle large images safely.

### 10d. Encryption — Full FS Path via `encryptBundle`

The main app uses the **same encryption path as in-app messages** — `ContactManager.encryptBundle(data:for:)`. This function already handles the complete forward secrecy protocol: pop the oldest inbound prekey if available, generate an ephemeral key pair, derive the session key via ECDH(ephemeral, prekey), attach any pending prekey batch, and produce a properly formatted `OccultaBundle`. When prekeys are exhausted, it falls back to the long-term path and signals the recipient to generate a fresh batch. For PQ contacts, ML-KEM secrets are mixed into every session key.

**There is no separate "share encryption path."** Shares get identical cryptographic protection to in-app messages — including forward secrecy when prekeys are available.

```
1. Read each file's content from the session directory.
2. Construct Occulta.File objects with UUID-based names and the file extension from the manifest.
3. Assemble a Basket containing all files.
4. JSON-encode the basket.
5. Call ContactManager.encryptBundle(data: encodedBasket, for: manifest.contactIdentifier)
   → This internally handles FS vs. fallback, PQ hybrid vs. classical, and pending batch delivery.
6. Write the returned OccultaBundle data to a .occ temp file.
7. Immediately delete all plaintext files from the session directory.
```

**The entire sequence (steps 1–7) is wrapped in a `do/catch`.** If any step fails — encoding, encryption, OOM on `AES.GCM.seal`, or file I/O — the `catch` block immediately deletes the entire session directory before rethrowing or presenting the error. Plaintext files must never persist after a failed encryption attempt.

```swift
do {
    // Steps 1–7
    let occData = try contactManager.encryptBundle(data: encodedBasket, for: identifier)
    try occData.write(to: occTempURL)
    try FileManager.default.removeItem(at: sessionDir)
} catch {
    // Plaintext cleanup on ANY failure — non-negotiable.
    try? FileManager.default.removeItem(at: sessionDir)
    throw error
}
```

### 10e. Large File Consideration

For very large files (video), reading the entire file into a `Data` object may cause memory pressure even in the main app. The `Basket` / `File` model stores file content as `Data` inline, and `encryptBundle` JSON-encodes the entire basket before calling `AES.GCM.seal`, which requires the full plaintext in memory.

This is an existing limitation of the encryption architecture, not specific to the share extension. The same constraint applies when encrypting a large video from within the main app via `ComposableMessage`. For now, the practical limit is the device's available RAM. Future improvement: chunked encryption with a streaming authenticated cipher (AES-GCM-SIV or ChaCha20-Poly1305 with chunked framing). This is out of scope for this feature.

If `encryptBundle` fails due to memory pressure, the `do/catch` in Step 10d deletes the session directory immediately. The error is surfaced to the user: "This file is too large to encrypt. Try sharing fewer files at once."

### 10f. Present Share Sheet

After encryption produces the `.occ` file (which contains a properly formatted `OccultaBundle` — identical to what in-app encryption produces):

1. Present `ShareLink` or `UIActivityViewController` with the `.occ` file.
2. User selects a transport channel (AirDrop, iMessage, email, etc.).
3. After sharing completes (or is cancelled), delete the `.occ` temp file.

The recipient decrypts this `.occ` file through the normal `decrypt(bundle:)` path, including prekey consumption and forward secrecy state updates. There is no special handling for "shared" vs. "in-app" bundles — they are structurally identical.

---

## Step 11: Memory Zeroing

### Main App (after encryption)

1. The plaintext `Data` buffers (file contents, JSON-encoded basket) must be zeroed before deallocation.
2. Swift does not guarantee zeroing on `Data` deallocation.
3. Use `withUnsafeMutableBytes` to overwrite:

```swift
var sensitiveData = Data(...)  // plaintext
sensitiveData.withUnsafeMutableBytes { buffer in
    memset(buffer.baseAddress!, 0, buffer.count)
}
sensitiveData = Data()  // release
```

4. Apply this to: each file's raw content `Data`, the assembled JSON-encoded basket `Data`, and the decrypted manifest `Data`.

### Extension (after contact selection)

5. After the user selects a contact, zero the decrypted contact list immediately. Overwrite every decrypted `Data` buffer (identifiers, display names) with `withUnsafeMutableBytes` + `memset` before releasing. For `String` values, reassign to `""`. Retain only the selected contact's identifier.
6. Zero the share index symmetric key `Data` buffer after the last decryption operation. The SE key reference can be released normally (it wraps an SE handle, not raw key material).

---

## Step 12: Cleanup

### Main App — On Every Launch and `scenePhase == .active`

Sweep the `pending/` directory in the shared container:

1. List all subdirectories.
2. For each session directory:
   a. If it contains a `manifest.enc`, check the timestamp inside. If older than 1 hour, delete the entire session directory.
   b. If it has no manifest (interrupted session), delete immediately.
3. This catches orphaned sessions from: user cancelling the extension, app crashes, main app failing to launch.

### Main App — After Successful Encryption

Delete the session directory immediately after the `.occ` file is produced (already handled in the `do` block of Step 10d). Do not wait for the share sheet to complete — the plaintext files are no longer needed once encryption succeeds. If encryption fails, the `catch` block deletes the session directory before rethrowing.

### Extension — On Cancellation

If the user cancels the extension (taps Cancel or swipes away), delete the session directory in the extension's `viewDidDisappear` or `didCancel` handler. This is best-effort — if the extension is killed before cleanup runs, the main app's sweep catches it.

---

## Step 13: Security Invariants — Checklist

Every item must be true at all times. A violation of any item is a shipping blocker.

1. **No plaintext contact data in the shared container.** The `ShareableContact` fields are AES-GCM encrypted with the share index key. The manifest's contact identifier is inside an AES-GCM encrypted blob.

2. **No key material in the shared container.** The shared store contains only encrypted display names and identifiers. No public keys, no ML-KEM secrets, no prekey state, no private key references.

3. **The share index SE key never touches the main contact database.** It encrypts only the `ShareableContact` index and the manifest. Different SE key, different HKDF info string, different purpose.

4. **The identity SE key, local DB key, and prekeys are never in the shared access group.** The test proved that migrating them is impossible. They remain in the main app's default access group, inaccessible to the extension. All contact encryption uses the main app's crypto managers, which run only in the main app process.

5. **Every file in the shared container has `.completeFileProtection` set explicitly.** `FileManager.copyItem` preserves the source file's protection class — directory-level protection is NOT inherited. Every `copyItem`, every `Data.write`, and every `manifest.enc` write must be followed by an explicit `setResourceValue(.complete, forKey: .fileProtectionKey)`. The `ShareIndex.sqlite` and its WAL/SHM companions are also explicitly protected.

6. **Original filenames are not stored as filesystem names.** Files are named `0.tmp`, `1.tmp`, etc. Original extensions are recorded only inside the encrypted manifest. Filesystem inspection of the shared container reveals no filename metadata.

7. **EXIF stripping happens before encryption, in the main app.** The extension never reads image content — it copies files as opaque blobs. The main app strips EXIF from images before building the `Basket`.

8. **The extension never performs ECDH with the identity key, never derives transport keys, and never encrypts messages.** It reads an encrypted contact list and copies files. That is the full extent of its cryptographic and filesystem operations.

9. **The manifest is encrypted.** It contains the contact identifier (relationship metadata). An attacker inspecting the shared container sees an opaque `.enc` blob.

10. **Orphaned plaintext files are cleaned up.** The main app sweeps `pending/` on every activation. Sessions older than 1 hour are deleted. Sessions without a manifest are deleted immediately.

11. **Shares use the same encryption path as in-app messages.** `ContactManager.encryptBundle` handles forward secrecy (when prekeys are available), PQ hybrid key derivation (for PQ contacts), and pending batch delivery. There is no separate "share encryption path" that bypasses FS.

12. **Encryption failure triggers immediate plaintext cleanup.** The entire encryption flow is wrapped in a `do/catch` that deletes the session directory on any failure — OOM, encoding error, ECDH failure, or I/O error. Plaintext files never persist after a failed encryption attempt.

13. **Decrypted contact data is zeroed in both processes.** The main app zeros file content and basket `Data` after encryption. The extension zeros the decrypted contact list after picker selection. The share index symmetric key `Data` is zeroed after use.

---

## Step 14: New Files Summary

| File | Target | Purpose |
|---|---|---|
| `ShareIndexKeyManager.swift` | Main app + Extension | SE key in shared group, HKDF derivation, AES-GCM encrypt/decrypt for index |
| `ShareableContact.swift` | Main app + Extension | SwiftData model for the encrypted contact index |
| `ShareManifest.swift` | Main app + Extension | Codable struct for the encrypted handoff manifest |
| `ContactManager+ShareIndex.swift` | Main app only | `syncShareIndex()` — full rebuild of the shared index after mutations |
| `ShareViewController.swift` | Extension only | Extension entry point, contact picker, file intake, manifest write |

No existing files are modified except:
- `OccultaApp.swift` — call `syncShareIndex()` on launch / `scenePhase == .active`
- `ContactManager.swift` — call `syncShareIndex()` after save/delete operations
- `Info.plist` (main app) — register `occulta://` URL scheme
- `Info.plist` (extension) — activation rule

---

## Step 15: What Happens If the SE Key Is Lost

If the user erases the device or restores from a backup that doesn't include the Keychain, the share index SE key is gone. The shared SwiftData store becomes undecryptable.

This is the correct behavior. The main contact database is also undecryptable in this scenario (its SE key is also gone). The main app detects this on launch (identity key missing → onboarding flow). The share index is rebuilt from scratch after the user re-creates their identity and re-exchanges contacts.

No special recovery path is needed. The share index is a derived, secondary data source. Its loss is always accompanied by the loss of the primary data, which already has its own recovery UX (re-exchange).
