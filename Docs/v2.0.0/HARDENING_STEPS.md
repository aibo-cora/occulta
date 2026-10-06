# v2.0.0 — Hardening Steps

**Status:** Proposed, 2026-09-30. Threat model and related tracked items: [README.md](README.md).
Staging: [ROLLOUT_PLAN.md](ROLLOUT_PLAN.md). What each step buys:
[PROTECTION_ASSESSMENT.md](PROTECTION_ASSESSMENT.md).

Code references are against `3319fd7`. Line numbers drift, so re-check them before citing.

## The list

**A. Close the device-seizure hole**
1. Make a diceware phrase an input to every depth's key, including the vault's
2. Use the Secure Enclave for every guess, not once
3. Make every row open under every depth's key, with filler where the row doesn't belong
4. Update every depth's slot on every write
5. Bind the small sealed fields to their row and field

**B. Protect messages the adversary already holds**
6. Send prekeys during the in-person exchange
7. Show or require post-quantum per contact
8. Authenticate the exchange peer, not just that it's close
17. Keep message keys behind the depth keys (added 2026-10-04; numbered last so earlier references
    stay valid)

**C. Leave nothing outside the app's own storage**
9. Add a CI check that blocks APIs that leave traces in the OS
10. Shrink the radio fingerprint
11. Keep the app's public face ordinary

**D. Harden the only input an attacker controls**
12. Fuzz the `.occ`/`.occbak` decoders and the share extension
13. Keep keys in memory only briefly

**E. Protect the supply chain**
14. Finish the distribution-build signing checks
15. Protect the developer account with a hardware key, and get an independent review

**F. Outside the code**
16. What at-risk users need to do on the device itself

**Not on the list, deliberately:** a panic-wipe button. See the end of this document.

---

## A. Close the device-seizure hole

### 1. A diceware phrase as a key input for every depth

**Why.** The identity, local-DB, custody, prekey and Secure Mode keys need only an unlocked device. The
vault key accepts the device passcode as an alternative to Face ID. The device passcode is the secret a
well-resourced adversary most often gets. With it, plus code running on the phone, every depth decrypts
and duress is a UI convention. Only a secret that is never stored on the phone changes that. The
secret is an app-generated 7-word phrase per depth, fed into key derivation. It replaces the PIN, and
with it the 6-digit verifiers, which crack in under a second and reveal how many depths exist. Bug 62's
collision check disappears as a side effect: at ~90 bits an accidental collision isn't worth guarding.

**Evidence.**
- `.privateKeyUsage` + `WhenUnlockedThisDeviceOnly`: identity
  ([Key+Manager.swift:101](../../Occulta/Services/Key+Manager.swift)), local DB (`:504`), custody
  (`:752`), Secure Mode (`:937`), prekeys ([PrekeyManager.swift:46](../../Occulta/Features/Forward+Secrecy/PrekeyManager.swift)),
  share index ([ShareIndexKeyManager.swift:87](../../Occulta/Features/ShareExtension/ShareIndexKeyManager.swift)).
- Vault key: `[.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode]` (`Key+Manager.swift:653`).

**Requirements already in the spec:** 7 words with PBKDF2, or 6 with Argon2id — never 6 with PBKDF2
(§4). Every depth's phrase is the same length, and phrases are app-generated and not editable (§3).
Entry never goes through the ordinary keyboard (§4).

**Tracked:** Bug 119; Bug 62 Gaps 1a/2; spec §1.

### 2. The Secure Enclave inside every guess

**Why.** If the Enclave's contribution is a fixed value (`ECDH(SE_priv, G)`), one call during extraction
captures it, and guessing moves off the phone to GPU or ASIC farms. Feeding the stretched phrase into
the Enclave operation means each guess costs one Enclave call on that specific phone. At 7 words this
is margin, not the main line of defence. It is the margin that matters if the adversary has a Secure
Enclave exploit, which at this level has to be assumed.

**Ships with 1, not after it.** Adding it later changes the key, which forces a second full reseal.

**Tracked:** spec §1, requirement of 2026-09-29.

### 3. Every row opens under every depth's key

**Why.** If a depth-2 row is sealed only under depth 2's key, a surrendered duress key gets an
authentication failure when it reaches that row. The failure is proof that something is hidden, and it
also counts how much. This is the Bug 109 tell, but on every row not visible at the examined depth
instead of on one field. Every row must decrypt cleanly under every depth's key: to real content where
it belongs, to filler everywhere else.

**This is the open design problem** and most of the work. Contacts make it harder than the vault,
because one contact can be visible at several depths.

**Tracked:** spec §2 (unresolved); Bug 109.

### 4. Update every depth's slot on every write

**Why.** An adversary who images the phone more than once can compare the images without any key. The
real depth's rows change daily and the duress depths' rows almost never change, so the comparison
points at the real one. Each write must reseal every depth's slot with fresh nonces.
`backup-export-meta.dat` (`ExportMetaSlotCodec`) already works this way, and custody shards reseal the
survivors on deletion since Bug 130. Everything else per-depth touches only its own depth's bytes.

**Tracked:** Bug 120; spec §2, second requirement.

### 5. Row and field binding for the small sealed fields

**Why.** `VaultEntry.visibleThroughDepth`/`.deletionToken`, `BackupEncryptionKey.depth`/`.deletionToken`,
`Contact.Profile.originDepth`/`.visibleThroughDepth`/`.globalTrusteeDepth` and
`PendingShamirSecretRestore.attributeID`/`.deletionToken` all seal through `Data.encrypt(using:)` with
one fixed AAD byte. A value copied from one row to another therefore decrypts cleanly. That doesn't
matter while code on the phone can forge these values outright. It becomes a real gap once steps 1–4
make forging impossible. Use an AAD built from the row's `id` and a field tag, as `VaultEntry.aad(for:)`
already does. Doing it in the same migration costs nothing extra.

**Tracked:** Bug 123 (subsumed into 119); spec §2, requirement of 2026-09-26.

---

## B. Protect messages the adversary already holds

### 6. Prekeys in the in-person exchange

**Why.** The exchange sends no prekeys, and batches are generated only on receipt
(`PrekeyManager.defaultBatchSize` is 15). So the first message in each direction is a long-term
fallback bundle, and so is roughly 1 in 16 after that. An adversary who keeps those files and later
takes the phone can open every one of them. iCloud Messages backups are a standing copy. Sending a
batch during the exchange gives every message forward secrecy from the first.

**Constraints.** Old clients ignore the new field, and messages from an old client still arrive as
fallback. Test the exchange in both directions between old and new versions. The payload's size must
not depend on whether Secure Mode is on.

**Design:** [Prekey Continuity](../Features/Prekey%20Continuity/DESIGN.md), proposed 2026-10-06. Its §3.2 is
this step. Seeding covers only the first message; the design's §3.1 and §3.3 cover the 1 in 16.

**Tracked:** new. The measurement comes from the register's note on 82a.

### 7. Show or require post-quantum per contact

**Why.** ML-KEM runs only on iOS 26+ (`PostQuantumProvider`, `#available(iOS 26, *)`). Any pair where one side is
older gets classical crypto only. A well-resourced adversary records traffic now to decrypt later.
Show each contact's post-quantum status, and give at-risk users a setting that refuses to send
classical-only messages.

**Tracked:** new.

### 8. Authenticate the exchange peer

**Why.** The session runs with `securityIdentity: nil`
([Exchange+Manager.swift:148](../../Occulta/Services/Exchange+Manager.swift)) and accepts every
invitation (`:768`). The control that exists is proximity plus the diceware comparison. If the user
skips the comparison, someone physically close can win the distance check and sit in the middle.
Either make the comparison mandatory before a contact saves, or implement `didReceiveCertificate`.

**Tracked:** register §B, §3.2 (P1).

### 17. Message keys behind the depth keys

**Status:** decided 2026-10-04. The design is in the spec, §2, "message keys must not route around the
layer keys".

**Why.** Steps 1–5 seal the database, but the keys that open messages are outside it. Prekey private
keys are Enclave keys tagged `prekey.<contactID>.<uuid>`
([Prekey.swift:61](../../Occulta/Features/Forward+Secrecy/Prekey.swift)), and the passcode is enough
to use them. With steps 1–5 alone, a surrendered duress phrase plus a keychain listing gives the
adversary three things:
- **The hidden contacts.** The tags name them.
- **How often each one messages.** Image-to-image changes in tag counts show it.
- **The content of their classical-only messages.** Those modes need only the prekey or identity key.
  Pairs with ML-KEM are already safe, because their derivation also needs the ML-KEM secrets stored in
  the contact's record.

**What changes.**
1. **17a. A per-contact secret for classical-only pairs**, mixed in the way ML-KEM's secrets are. New
   pairs derive it at the exchange. Existing pairs exchange it in band, over forward-secret messages.
2. ~~**17b. Random prekey tags**, with the map kept in the contact's record.~~
3. ~~**17b. Random padding:** each install creates a random number of dummy Enclave keys, once. Nothing
   ever deletes or replaces them. In one image they hide a few hidden contacts' prekeys. Replacing
   dummies each session was considered and rejected: it adds almost nothing measurable, because the
   transport usually shows the same messages.~~

~~Prekeys stay in the Enclave. Moving them into the record would break forward secrecy against an image
taken before the phrase is obtained.~~

**17b superseded, 2026-10-06** ([Prekey Continuity §9](../Features/Prekey%20Continuity/DESIGN.md), D9).
Prekeys stay Enclave keys, but their wrapped blobs move into the contact's sealed record, generated through
CryptoKit, and no prekey is a keychain item any more. A keychain Enclave key is itself a blob on disk with a
creation date, and nothing documents that deleting it revokes an older copy, so the reason above didn't hold.
Software keys in the record are the fallback only with the owner's explicit sign-off.

4. **17a. A sender fingerprint keyed with the per-contact secret** instead of the public key. Today
   anyone with the user's public key, which every contact has, can tell which `.occ` files the user
   sent. Group files carry one tag per recipient entry in place of the single outer fingerprint. It
   ships in 17a because 17a already changes the wire format and its negotiation.

**Open, needs a decision.** This step doesn't close these, and none is accepted:
- **Senders on old versions.** Their classical-only messages stay readable until they update.
- **Transport records** still show that a relationship exists. Step 16's guidance has to cover this.
- **Repeated images** show prekeys appearing and disappearing that the surrendered depth can't account
  for. *Changed by D9:* prekey changes become row writes, which step 4 covers like any other. This holds only
  once the legacy keychain prekeys have retired (30 days after the last use of their batch). Until then it
  applies to them as written.
- ~~**More hidden contacts than the random padding covers** make the total stand out in one image.~~ Moot
  under D9: no padding, no prekey keychain items. Legacy keychain prekeys remain countable until they retire.
- **Where prekeys live.** Decided 2026-10-06 (D9, above).
- ~~**The padding range** itself.~~ Moot under D9. The prekey batch size and refill threshold are decided
  separately: 15/5 for v2.0.0 ([Prekey Continuity](../Features/Prekey%20Continuity/DESIGN.md) D4,
  2026-10-06).
- **Mixed groups.** A group file keeps the old, attributable fingerprint while any recipient hasn't
  upgraded.

**Tracked:** new. Found 2026-10-04 while closing the assessment's "unopened messages" residual.

---

## C. Leave nothing outside the app's own storage

### 9. CI check for APIs that leave OS traces

**Why.** The worst leaks so far were outside the app's own storage: the keyboard's learned-words file
(register F1) and Universal Clipboard (F2). Both were fixed by hand, field by field, while one correct
instance of each already existed in the code. Add a test or lint that fails the build on:
- a text input without `.autocorrectionDisabled()`;
- a bare `UIPasteboard` setter, instead of `UIPasteboard.copySensitive(_:)`;
- `NSUserActivity`, Core Spotlight, user notifications, or Siri/Intents donations;
- a new `@AppStorage`/`UserDefaults` key.

None of the APIs in the third bullet is used today, and the check keeps it that way.

**Tracked:** F1 names the lint as "still worth doing"; the wider scope is new.

**Status: built 2026-10-05**, `OccultaTests/OSTraceTests.swift`, on `v2.0.0/os-trace-ci-check`. It runs
inside the existing `OccultaTests` command, so CI needs no new step. Planted violations of each kind
fail, which meets Stage 0's done-condition for this step.
- **What the first run found.** 27 inputs had no `.autocorrectionDisabled()`, including all three
  message compose fields, the Sign editor, the identity-challenge question, and three contact or
  recipient search fields. F1's fix in 2026-08 covered three inputs, and every input added since shipped
  without it. All 27 are fixed.
- **System text selection counts as a pasteboard write.** Its Copy menu skips `copySensitive`, so it
  has no `.localOnly` and no expiry. The identity challenge's incoming question is no longer
  selectable.
- **Search fields.** SwiftUI's search field takes `.autocorrectionDisabled()` only from *after*
  `.searchable` in the chain. A modifier placed before it is ignored. `SearchableModifierPlacementTests`
  measures this on the real `UISearchTextField`. On iOS 26 the field also defaults to autocorrection
  off. The check still requires the modifier, because that default is untested on 18.6.
- **Scope.** The check reads source text. A modifier applied to a container instead of the field
  fails, deliberately. `UserDefaults` keys are checked against the list in `SECURITY_CHECKLIST.md`.

### 10. Shrink the radio fingerprint

**Why.** The Bonjour service `_peer-data-ex._tcp`/`_udp` ([Info.plist](../../Occulta/Info.plist),
`Exchange+Manager.swift:40`) is unique to Occulta. It is broadcast over Bluetooth and Wi-Fi while
advertising, so a passive scanner nearby learns that an exchange is happening. The name must be
declared in `Info.plist`, so it can't be randomized. Advertise only while the exchange screen is in the
foreground, and confirm that advertising stops on every exit path, backgrounding included (`:207`,
`:211`). Document what remains. Random UUID peer names (`:146`) are already right.

**Tracked:** new.

**Status, 2026-10-05.** The exit paths were checked against the code, on `v2.0.0/exchange-advertising-teardown`.
- **Already right:**
  - Advertising starts 3 s after the user taps "Exchange Keys", not when the screen opens.
  - Each exchange gets a fresh random peer name, with no discovery info.
  - It stops on timeout, failure and save.
  - It stops on backgrounding (`KeyExchangeLiveView`, shown in every phase but resting).
  - A 30 s watchdog stops it if ranging updates stop.
- **Fixed:** leaving the screen. Nothing stopped the exchange when the screen went away, so teardown
  depended on the `@State` manager being freed, which isn't guaranteed to stop the advertiser, with
  the watchdog as the only bound. `KeyExchange` now calls `finish()` in `onDisappear`.
  `KeyExchangeTeardownTests` hosts the real screen mid-exchange and checks that removing it stops the
  exchange; it failed before the fix.
- **What remains, and can't be fixed:** the service name is unique to Occulta and fixed in
  `Info.plist`. Anyone in radio range during the seconds of an exchange can tell Occulta is in use.
  They see no peer name that links two exchanges.
- **Open, needs a decision: the joined Wi-Fi network.** MultipeerConnectivity advertises over the Wi-Fi
  network the phone is joined to, not only over the direct peer-to-peer radio. Everyone on that network
  receives the mDNS announcement, and its equipment may log it, a record held by a third party and kept
  longer than anything a nearby scanner sees. Closing this means replacing MultipeerConnectivity with
  Network.framework restricted to the peer-to-peer link. That is a rewrite of the exchange transport,
  and it drops Bluetooth, which the 25 cm exchange may not need.

### 11. Keep the app's public face ordinary

**Why.** Having Occulta installed, and when it was used, can be established without touching the app.
Apple can produce App Store download history, and the OS keeps its own app-usage records (Screen Time /
Biome). No code hides either. The app therefore has to be an ordinary thing to have installed, and its
own words must not overclaim. `Docs/Features/Secure Mode/USER_GUIDE.md` is drafted as shipping copy:
line 100 reads "Even law enforcement cannot decrypt them…", and the heading at line 221 is "Can
Apple/Government Access My Data?". The register also notes that overclaiming a protective guarantee has
never been audited for. Route both through counsel in one pass.

**Tracked:** register §E (Tier 3, P1).

---

## D. Harden the only input an attacker controls

### 12. Fuzz the decoders and the share extension

**Why.** In an app with no network, `.occ`/`.occbak` parsing is the only input an attacker controls.
`ShareViewController` runs that parsing in a separate process and has no tests. Nothing is fuzzed.
Sending a crafted file is the cheapest way to get code running inside Occulta, and until step 1 lands,
code running there can use every key.

**Tracked:** register D5, D6 (P2). Given the above, P2 is low for this threat model.

### 13. Keep keys in memory only briefly

**Why.** Keys cached for a session can be read by a live exploit while the phone is unlocked. Drop them
when the app goes to the background or locks. The planned C2 cache ("scene-phase-scoped, cleared on
background") must follow the same rule, and so must the session-cached `layerKey_D` in spec §4. This
narrows the window. It does not defeat a full-device implant on an unlocked phone, and nothing an app
does can.

**Tracked:** new; related to register C2.

---

## E. Protect the supply chain

### 14. Finish the distribution-build signing checks

**Why.** Check the distribution build before submitting:
1. `get-task-allow` must be `false` on the app and both extensions. When it is `true`, any process
   can attach a debugger and read keys.
2. The embedded profile must be an App Store profile.
3. The distribution profile must add no entitlement beyond app groups.
4. `codesign --verify --deep --strict` must pass.

**Last recorded state** (`SECURITY_CHECKLIST.md`, "What is still not verified", and the 2026-08-26
note): not done, because this machine has no Apple Distribution identity. Check whether it was done
for 1.11.x, and record the result.

**Tracked:** register D1.

### 15. Developer account and independent review

**Why.** Whoever controls the Apple developer account can ship an update that extracts data. A solo
developer is one person that an adversary with this level of resources can compromise or compel.
- Put a hardware security key on the Apple ID.
- Sign releases on a dedicated machine.
- Publish a source hash for every tag.

No independent person has reviewed the code yet. Everything so far was written and reviewed in the
same sessions (`SECURITY_CHECKLIST.md` sign-off, condition 3).

**Tracked:** account hardening is new; review is register D4 (P1).

---

## F. Outside the code

### 16. What at-risk users need to do

**Why.** Every Occulta key gated only by "device unlocked" is as strong as the device passcode, until
step 1 ships, and afterwards for everything step 1 doesn't cover. At-risk users need:
- **A long alphanumeric passcode.** Apple calibrates each passcode attempt to about 80 ms, so once a
  tool gets past the Enclave's retry limits, a 6-digit passcode falls in about a day at worst.
- **Lockdown Mode.** It is the only defence against the implant scenario, and it is Apple's.
- **The phone powered off whenever it may leave their control.** Before first unlock, nothing opens.
- **Knowing that side button + volume disables Face ID** until the passcode is entered.

The phrase setup screen is the natural place to show this once. Its wording depends on step 11.

**Tracked:** new.

The guidance must also say that the transport keeps its own records. An ongoing exchange of `.occ` files
with a hidden contact is visible in Messages history and its backups, whatever the app does (step 17).

---

## Not recommended: a panic-wipe button

A wipe during an examination can be detected. It can itself carry legal consequences for the user, and
it confirms there was something to destroy. Duress depths serve the same need without either problem.
The open "Erase All Data" item in the register (`Docs/Bugs/v1.10.0/Erase-All-Data-…`) should be read as
keeping the existing erase from being a lever for a coercer, not as a reason to add a faster wipe.
