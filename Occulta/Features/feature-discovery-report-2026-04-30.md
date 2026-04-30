# Occulta Feature Discovery Research Report
**Date:** April 30, 2026  
**Scope:** Competitive app analysis, privacy community pain points, and original feature proposals  
**Methodology:** Web search across App Store changelogs, developer documentation (WWDC 2025, iOS 26 APIs), Privacy Guides community, Hacker News, press/security research publications, journalist digital security resources

---

## TASK 1 — Competitive App Analysis

Findings are grouped by theme. Each item notes the source app, the feature, and a compatibility note for Occulta's zero-server, Secure Enclave-first architecture.

---

### Theme 1: Key Verification UX

**Signal (iOS) — Safety Numbers**  
Signal's verification model has evolved: safety numbers are now per-conversation (not per-user), reducing stale fingerprint confusion. A share button lets users send a safety number over any third-party channel (email, another messenger). The new Sparse Post-Quantum Ratchet (SPQR) adds quantum-resistant ratcheting to the Signal Protocol (2025). GitHub issues #991 and #1914 document years of user confusion between "key changed" and "man-in-the-middle attack" — Signal has not fully resolved the conceptual clarity problem.  
*Occulta compatibility:* The concept of a "re-verify existing contact" flow — triggering a second Diceware ceremony for an established contact on demand — is absent from Occulta. High-value addition for users who receive a new device (and want to re-confirm identity without creating a new contact record).

**iMessage Contact Key Verification (iOS 17.2+)**  
Apple's CKV uses a Key Transparency (KT) log-backed system providing cryptographic proofs that the key your device trusts for a contact is the same key Apple's servers have on record. In-person verification requires comparing a short string side-channel. Target audience is explicitly "journalists and activists facing extraordinary digital threats." Critical limitation: requires an iCloud account and Apple's KT server infrastructure.  
*Occulta compatibility:* Occulta's offline-first model is architecturally superior. However, the concept of a **local per-contact key observation log** (tracking when the key was first seen, and alerting if it changed since the last UWB ceremony) would bring a similar trust-over-time guarantee without any server dependency. This aligns with the already-planned audit log and could be surfaced per-contact.

**Threema (iOS) — Verification Tiers**  
Threema displays three visible verification tiers for each contact: (0) unknown identity, (1) identity confirmed via email/ID entry, (2) identity confirmed by QR scan in person. Users understand at a glance their trust level. No phone number required; identity is a random Threema ID generated on first launch.  
*Occulta compatibility:* Occulta's planned "key trust level badges" (UWB / QR / manual) directly cover this. No feature gap, but Threema's UX of making the tier immediately scannable on the contact list card is worth matching.

**Keybase (stale since Zoom acquisition, 2020)**  
Before going dormant, Keybase's standout feature was **social identity proof** — cryptographically signing a public statement linking your Keybase key to your Twitter, GitHub, Reddit, and other accounts. Per-device NaCl keys; private key never leaves the device. Public, auditable key directory.  
*Occulta compatibility:* The social proof concept requires Keybase's server infrastructure, so direct replication is out. However, a **portable signed identity assertion** — a small blob signed by the SE identity key stating "I control the handle @username on platform X" — could be generated locally, shared via the existing Share Sheet extension, and manually verified by any recipient. This is fully serverless and compatible with Occulta's architecture.

---

### Theme 2: Offline / P2P Encrypted Communication

**Briar (Android only — no iOS version exists)**  
Briar's architecture is the most relevant P2P model for Occulta's philosophy. Key design patterns: (1) multi-transport operation over Bluetooth, Wi-Fi Direct, Tor, and memory-card relay in order of availability; (2) delay-tolerant store-and-forward via the Bramble Sync Protocol — messages queue locally until the next proximity or internet connection; (3) contact exchange by QR code in person only; (4) local forum and blog features that replicate across the mesh.  
*Occulta compatibility:* High. Briar is Android-only, leaving this entire design space unaddressed on iOS. iOS 26's Wi-Fi Aware framework and Multipeer Connectivity together provide the transport primitives needed to replicate Briar's delivery model on iOS for basket delivery.

**Session (iOS)**  
Session requires no phone number (registration is a random cryptographic keypair). Messages are onion-routed over a decentralized node network, hiding sender/receiver IP from infrastructure. End-to-end encrypted with open-source, audited protocol.  
*Occulta compatibility:* Session's onion routing is inherently node/server-adjacent. Occulta's zero-server model is a stronger guarantee. No direct feature gap to adopt, but Session's "no phone number required" positioning is a competitive talking point Occulta shares and should emphasize.

**OnionShare (iOS — send only)**  
OnionShare generates a .onion address for anonymous file sending over Tor. The iOS version (App Store, iOS 15+) can only send files, not receive them — a well-documented limitation caused by iOS background operation restrictions. Requires active device presence.  
*Occulta compatibility:* The anonymity model (sender unknown to recipient) is architecturally incompatible with Occulta's identity-bound key exchange. However, the concept of a **one-time anonymous drop** — where a file is encrypted to a specific public key and placed in a transient location without revealing sender identity — is a feature gap Occulta could address with a "send anonymously" mode that omits sender identity from the basket envelope.

---

### Theme 3: Encrypted Vault & Secret Management

**Strongbox (iOS) — Key Features**  
Strongbox 1.60.x (2025) introduced: SSH key storage and SSH agent (macOS), TOTP codes (QR / manual / Steam), hardware YubiKey support with **hardware key caching** (stores challenge-response so you don't need the YubiKey for every unlock — only periodically), passkey storage within KeePass database, **Wi-Fi Sync** (local network database sync, no cloud), security audit reports (flagging weak/reused/old passwords), import migration from 1Password, Bitwarden, Enpass.  
*Occulta compatibility:* Hardware security key support (YubiKey NFC challenge-response) is a meaningful gap in Occulta. Wi-Fi Sync without cloud is architecturally relevant. Security auditing of vault item health is a low-complexity, high-value add.

**KeePassium (iOS) — Key Features**  
YubiKey NFC and Lightning support for vault unlock, TOTP inline with entries, custom entry fields, database health reports, and — notably — an **independently published security audit** (the only KeePass-compatible mobile app to have one). Audit transparency is a significant trust signal in the privacy community.  
*Occulta compatibility:* Hardware key support (as above). Published audit is a positioning/marketing action rather than a feature, but privacy communities explicitly look for it. A vault health check feature (surface weak, old, or duplicate vault items) is feasible locally.

**1Password (iOS) — Travel Mode**  
Travel Mode removes designated vaults from the device entirely — keys are not just hidden but fully absent. The app reveals no sign that Travel Mode is active. Critical limitation: enabling/disabling Travel Mode requires a web session with 1Password.com, creating an internet dependency at precisely the moment users need it most (in transit, crossing borders).  
*Occulta compatibility:* High. This is the most cited gap in the privacy community for a fully offline-capable Travel Mode. A cryptographically sound, server-free equivalent is architecturally achievable on iOS (see Task 3, Feature 3).

---

### Theme 4: Encrypted File Workflows

**Cryptomator (iOS)**  
Open-source, encrypts both file contents and file names with AES-256. Fully integrated with the iOS Files app. Requires an underlying cloud or WebDAV storage provider — it is an encryption layer, not a storage solution. Recent iOS 26 update adds Liquid Glass icon. Files app integration is native.  
*Occulta compatibility:* Cryptomator's **filename encryption** is a meaningful gap. Occulta's basket manifest, when stored or cached, could reveal metadata (file count, approximate sizes, names) even without the content keys. Encrypting basket manifest entries (including filenames and MIME types) with a basket-specific key would prevent metadata inference from the basket container structure itself.

**Tresorit (iOS)**  
GDPR/HIPAA/ISO 27001 compliant encrypted file storage; business collaboration and admin policy enforcement. All cloud-based and server-dependent.  
*Occulta compatibility:* Low. Server-dependent architecture is a non-starter for Occulta.

**Signal Secure Backups (iOS 26, November 2025)**  
Signal launched encrypted local backups — a 64-character recovery key generated on-device, not transmitted to Signal's servers. Backups include all messages and media. Local backup (to user-owned storage) in active development for 2026.  
*Occulta compatibility:* The explicit "64-character recovery key generated on your device" UX pattern is worth adopting for Occulta's vault backup. Users understand the tradeoff (lose the key, lose access) better when it's framed this way. Occulta's Shamir SSS for vault key is more sophisticated, but a simplified "recovery key printout" UX could serve less technical users.

---

## TASK 2 — Privacy Community Research

Findings grouped by theme. Community sources: Privacy Guides community forums (discuss.privacyguides.net), Hacker News, Freedom of the Press Foundation (freedom.press), Electronic Frontier Foundation, journalist security publications.

---

### Theme 1: Key Verification UX — Persistent Confusion and Requests

Signal's safety number system remains a source of ongoing confusion even among security-aware users. The core problem is documented in multiple GitHub issues and forum threads: **when a key changes (after reinstall, new device), users who previously verified face a "CONFLICT" warning that looks identical to a MITM attack**. Signal's model requires users to re-verify via an out-of-band channel — phone call, in-person meeting, or another messaging app — adding real friction for non-technical contacts.

Privacy Guides Community thread "[iOS 17.2] Contact Key Verification" (late 2023, actively discussed into 2025) surfaced a recurring complaint: Apple's CKV and Signal's safety numbers require the same in-person string comparison, yet neither makes the verification ceremony feel trustworthy to lay users. **Users want a verification mechanism that feels as natural and un-skippable as scanning a QR code at a restaurant, not reading 60 digits aloud.** Occulta's UWB Diceware approach is the strongest answer to this demand, but the design insight is worth reinforcing in UX copy.

**Requested features from community:** (1) Automatic prompts to re-verify when a contact key changes; (2) visible "last verified date" per contact; (3) verification method displayed (in-person vs. out-of-band vs. unverified); (4) notifications if a contact's key has not been re-verified in N months.

---

### Theme 2: E2EE File Sharing on iOS — A Genuine Unsolved Gap

The Privacy Guides community thread "Are there any free E2EE file sharing options for iOS?" (December 2024) documents a complete absence of satisfactory options:

- OnionShare iOS: send only, receive broken, requires active device
- Magic Wormhole: desktop only, no native iOS app  
- Firefox Send: deprecated
- Wormhole.app (wormhole.app): requires a central relay server
- AirDrop: no encryption beyond transport TLS; recipient knows sender identity

The Privacy Guides file sharing recommendations page explicitly states the requirements: *no third-party remote server, open source software, iOS and Android native support.* **No app currently meets all criteria.** This is Occulta's exact architectural positioning — the community does not yet know Occulta exists, but the pain point is clearly documented and active.

A separate thread ("How to share/send big files safely?") from 2025 echoes the same gap for large file transfers (documents, video footage from field journalism).

---

### Theme 3: Journalist and Activist Tool Fragmentation

Freedom of the Press Foundation's 2026 Journalist's Digital Security Checklist recommends Signal (messaging) + OnionShare (file transfer) + 1Password for Journalists (vault). This means three separate apps, three separate key management systems, with no cryptographic linkage between identities. Sources verified in Signal are not automatically trusted in OnionShare or 1Password.

The journalist community's documented pain: **"I have five tools for encryption and none of them know about each other."** Key-per-app identity fragmentation means a source's key in Signal is unrelated to their key in any other tool. Every new tool requires a new verification ceremony.

Occulta's unified identity model — one SE-bound key per contact, used for all interactions (messages, files, vault access) — directly solves this fragmentation. The community is clearly asking for this, even if they haven't articulated it as "unified cryptographic identity."

Freedom of the Press Foundation also specifically highlights border crossing and device seizure scenarios as top concerns. 1Password Travel Mode is the current recommendation for vault protection, with the known limitation that it requires internet access.

---

### Theme 4: The No-Account, Local-First Demand Is Accelerating

The Electronic Frontier Foundation launched the "Encrypt It Already" campaign (January 2026), specifically pressuring companies to implement end-to-end encryption *by default* and to stop making accounts a prerequisite for privacy. Community sentiment on forums and HN is clear: **server-tied identity is a liability, not a feature.** An app that requires an account has an account that can be subpoenaed, deactivated, or used for metadata analysis.

Hacker News "Show HN: Secure Storage — an offline encrypted vault for iOS" (February 2026, item #47002399) attracted strong positive engagement. The developer's key selling point: "zero networking code in the app." Top comments explicitly praised this as increasingly rare and valuable.

HN "How HN: A messaging app that keeps all your data local" (August 2025) demonstrated appetite for entirely local contact management and P2P voice calls, confirming that the local-first model resonates with the developer-adjacent privacy community.

**Key community signal for Occulta:** Users actively distrust apps that *could* add server dependencies in a future update. Occulta's open-source, auditable, zero-network-code architecture would be a trust differentiator.

---

### Theme 5: Border Crossing and Device Seizure — A Specific, Recurring Pain Point

Across r/privacy, r/privacyguides, and the journalist security community, border crossing with encrypted devices is a frequently discussed high-stakes scenario. 1Password Travel Mode is cited in virtually every thread as the tool of choice — but its server dependency is a persistent complaint. The ideal described by users: **"toggle Travel Mode on the plane, before landing, with no internet connection, and have my sensitive vault contents be cryptographically non-existent by the time a border agent picks up my phone."**

The gap: no app currently offers this with zero server dependency. 1Password requires web access. VeraCrypt (hidden volumes) is desktop-only. iOS's built-in data protection helps but doesn't selectively hide subsets of an app's data.

---

### Theme 6: Post-Quantum Awareness Is Now a Mainstream Evaluation Criterion

Following Apple's PQ3 iMessage announcement (2024), Signal's SPQR (Sparse Post-Quantum Ratchet, 2025), and WWDC 2025's ML-KEM/ML-DSA APIs in CryptoKit, privacy-community users now routinely ask "is this app post-quantum safe?" when evaluating tools.

The "store now, decrypt later" threat model (adversaries capturing encrypted traffic today to decrypt when quantum computers arrive) is explicitly cited in r/netsec and privacy forums. **Apps without post-quantum key exchange are being dismissed by high-threat users.**

iOS 26's CryptoKit formally supports ML-KEM-768, ML-KEM-1024, ML-DSA-65, and ML-DSA-87 with Secure Enclave backing. HPKE combining ML-KEM and classical ECDH is supported via Apple's framework. Occulta's planned ML-KEM + ECDH P-256 hybrid on iOS 26+ is therefore both timely and technically well-supported by the platform.

---

## TASK 3 — Original Feature Ideas

Each idea is server-free, Secure Enclave-compatible, and not on the existing planned feature list.

---

### Feature 1: Cryptographic Panic Wipe

**Description:** A sub-second, irreversible key-destruction operation that permanently renders all Occulta vault contents and basket data unreadable — without deleting any files. The architecture uses a two-layer key hierarchy: the SE-bound identity key (persistent, replaceable only via a new UWB ceremony) protects contact keys, while a separate "vault-wrapping key" stored in a deletable iOS Keychain item protects all vault entries, basket manifests, and encrypted files. Triggering a Panic Wipe deletes the Keychain item in a single atomic call, making every piece of Occulta's stored data permanently inaccessible — indistinguishable from random bytes — without any file deletion that would be visible in iOS logs or forensic analysis. Because no data is deleted, the operation completes in milliseconds and leaves no temporal signature. An optional pre-populated "decoy vault" (a second set of innocuous vault items encrypted under a different key) can be configured to surface when the panic credential is re-entered, providing plausible deniability.

**Target Persona:** Journalist crossing a hostile border, human rights activist at risk of device confiscation, any user who needs to sanitize their device under physical duress.

**Why it fits Occulta's zero-server philosophy:** The operation is entirely local. No internet connection, no server call, no remote wipe infrastructure. The Panic Wipe works optimally on airplane mode — precisely when border crossings occur. Unlike MDM remote wipe, it cannot be blocked by putting the device in a Faraday cage.

**Technical constraint on iOS:** The SE does not support arbitrary on-demand deletion of SE-resident keys; SE keys persist until the app is deleted or explicitly rotated. The architecture therefore must use a Keychain item (with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and hardware binding) as the vault-wrapping key, not an SE key directly. This item is deletable via `SecItemDelete`. All vault and basket keys are wrapped by this item. Deleting the item without deleting the underlying encrypted blobs achieves the desired effect. The SE identity key survives and remains available for future contact establishment on a fresh vault.

---

### Feature 2: Proximity-Gated P2P Basket Delivery (Wi-Fi Aware / Multipeer)

**Description:** Encrypted baskets are delivered directly between nearby Occulta users via iOS 26's Wi-Fi Aware framework, with automatic fallback to Multipeer Connectivity (Bluetooth + peer-to-peer Wi-Fi) on older devices. When two contacts with an established UWB key relationship come within Wi-Fi Aware range (up to ~100m, 250 Mbps throughput), Occulta automatically detects their presence and delivers any queued outbound baskets. Delivery receipts are cryptographically signed with the recipient's SE identity key, providing non-repudiable acknowledgment. A local "outbox" maintains pending baskets; they are delivered automatically on the next proximity event, without any user interaction beyond app being foregrounded. This transforms Occulta into a delay-tolerant, store-and-forward system inspired by Briar's Bramble Sync Protocol — but on iOS.

**Target Persona:** Journalist exchanging large encrypted files in the field (no mobile data), activists in regions with internet shutdowns, any pair of frequent in-person collaborators who want zero internet dependency.

**Why it fits Occulta's zero-server philosophy:** Wi-Fi Aware is a device-to-device protocol requiring no access point and no internet. The existing UWB-exchanged key is reused as the authentication anchor for Wi-Fi Aware pairing via DeviceDiscoveryUI. This feature adds a transport layer without adding any server dependency. In complete internet blackout scenarios (natural disasters, network shutdowns), Occulta users continue to exchange encrypted files through physical proximity alone.

**Technical constraint on iOS:** Wi-Fi Aware requires iOS 26 and the new `WiFiAware` framework (announced WWDC 2025). On iOS 15-25, Multipeer Connectivity provides fallback transport (lower bandwidth, ~2-4 Mbps, shorter range). Background Wi-Fi Aware delivery in iOS 26 has improved capabilities but may still require the app to be in the foreground for initial pairing. Automatic background delivery of small notification-like baskets may be feasible using the Multipeer background transfer mode; large file delivery likely requires user interaction to confirm.

---

### Feature 3: Offline Travel Mode with Cryptographic Vault Concealment

**Description:** An entirely offline "Travel Mode" that cryptographically removes designated contacts and vault items from the device — not merely hides them in the UI. Distinct from the planned "duress PIN" (which locks the app's UI), Travel Mode re-encrypts the keys of designated "sensitive" items under a second secret (the travel key, derived from a separate passcode) and then removes all other access paths to those keys from the Keychain. The device can be powered on, the app opened under the primary credential, and inspected — the sensitive items simply do not exist. Not hidden, not locked: cryptographically absent. Deactivation requires both the travel key AND the original app credential, preventing coercive extraction of one without the other. Travel Mode can be activated and deactivated entirely offline, which is the critical differentiator versus 1Password's Travel Mode (which requires a web session).

**Target Persona:** Journalist crossing a border, lawyer protecting client data during travel, activist in a country where device inspection is common, any user who needs to credibly assert "I don't have that data on me."

**Why it fits Occulta's zero-server philosophy:** All operations are local Keychain writes and deletes. Activation on airplane mode before landing, deactivation after clearing customs — no internet required at any point. This is the exact scenario the privacy community has been asking 1Password to solve for years.

**Technical constraint on iOS:** The architecture requires that sensitive vault and contact items use keys structured as: `item_key = SE_identity_key_derive(travel_key, item_id)`. Removing `travel_key` from the Keychain (a simple `SecItemDelete`) makes all sensitive items inaccessible while the main vault (whose keys derive from the primary credential) remains fully functional. The travel key itself is stored in a Keychain item with `kSecAttrAccessibleWhenUnlocked` and can be deleted in a single call. CryptoKit's HKDF supports the required key derivation architecture.

---

### Feature 4: Hardware Security Key (YubiKey NFC) as Vault Second Factor

**Description:** Optional enrollment of a hardware FIDO2/HMAC-SHA1 token (YubiKey or compatible NFC device) as a second factor for vault unlock. When enrolled, unlocking the vault requires biometric authentication (SE-bound) AND an NFC tap from the registered hardware key. The YubiKey performs a challenge-response (HMAC-SHA1 OTP slot) that is combined with the biometric auth result to derive the vault-unwrapping key; neither factor alone decrypts the vault. The hardware key factor specifically defends against biometric coercion ("rubber hose" attacks) — an adversary who forces a fingerprint on the device still cannot access the vault without physical possession of the hardware key. An optional caching mode (similar to Strongbox's hardware key caching) stores the last challenge response for a configurable period, balancing security against convenience.

**Target Persona:** Security researcher, enterprise professional, journalist or activist who does not trust biometric coercion resistance, anyone who has previously used Strongbox or KeePassium with YubiKey and wants the same model for contact and file management.

**Why it fits Occulta's zero-server philosophy:** CoreNFC and the YubiKey challenge-response protocol operate entirely on-device. No internet required. The hardware key solely unlocks the vault-wrapping key; the SE identity key (used for contact key exchange) remains independent and SE-bound. These are orthogonal security layers.

**Technical constraint on iOS:** CoreNFC (iOS 13+) supports NDEF and ISO 7816 reads for YubiKey HMAC-SHA1 OTP slot 2. The Yubico iOS SDK is available and MIT-licensed. Lightning YubiKeys (YubiKey 5Ci) use MFi accessory protocol. USB-C YubiKeys are supported on iPhone 15/16 (USB-C) and newer. FIDO2/WebAuthn is also supported via `ASAuthorizationController` for full FIDO2 assertion flow without third-party SDK dependency.

---

### Feature 5: Delay-Tolerant Encrypted Message Queue ("Proximity Outbox")

**Description:** A local message queue that holds encrypted baskets for contacts who are currently unavailable (out of range, no internet) and delivers them automatically the next time the two devices come within proximity. User A composes and encrypts a basket using contact B's stored public key (from the original UWB ceremony) and places it in the Proximity Outbox. Occulta monitors for B's presence via Bluetooth Low Energy advertising (which iOS allows in background for apps with the bluetooth-central background mode). When B appears, Occulta prompts the user (or, for smaller baskets, delivers automatically) and provides a cryptographically signed delivery receipt from B's SE key. Multiple queued baskets for multiple contacts are managed independently. The queue is stored encrypted and survives app restarts and device reboots.

**Target Persona:** Journalist communicating with field sources in low-connectivity environments, activists operating in regions with intermittent internet, anyone who meets their contacts in person and wants to exchange files without orchestrating simultaneous online sessions.

**Why it fits Occulta's zero-server philosophy:** The queue lives entirely on the sender's device. Delivery requires physical proximity, not internet infrastructure. An adversary who intercepts or seizes the sender's device between composition and delivery sees only ciphertext encrypted to B's public key — they cannot read the content. There is no server queue, no metadata exposed to infrastructure.

**Technical constraint on iOS:** BLE background advertising is permitted for apps with `UIBackgroundModes: bluetooth-central` (peripheral detection) but Apple throttles BLE scan intervals when in the background. Reliable automatic detection is best-effort; a foreground notification ("B is nearby — deliver 3 pending baskets?") is a reliable UX alternative. Wi-Fi Aware (iOS 26+) provides a more capable background channel for detection and delivery of larger files.

---

### Feature 6: Threshold-Gated Group Document (M-of-N Collective Basket)

**Description:** A shared encrypted document whose decryption key is cryptographically split into N shares using Shamir Secret Sharing (already implemented in Occulta for vault key custody). One share is encrypted for each group member's SE identity key. The document can only be opened when M designated members physically gather, each contributing their share via a sequential UWB proximity ceremony. Each member's device decrypts their share locally, passes it to the coordinating device within the UWB session, and the key is reconstructed in RAM. The plaintext document is displayed in-session only; the reconstructed key is never persisted to disk and is purged from memory when the session ends or the app is backgrounded. Distribution of shares to new group members (or revocation of a member's share) follows the same UWB key-exchange ceremony used for all contacts.

**Target Persona:** Journalist team managing a shared sensitive document requiring quorum (e.g., a shared source contact list or evidence archive), legal team with client-privileged records requiring multiple partners present, activist cell with shared operational documents, any organization using Shamir custody for a shared secret that should only be accessed in-room.

**Why it fits Occulta's zero-server philosophy:** All Shamir share operations are local. Shares are distributed via the existing basket mechanism and encrypted to each member's SE identity key. No server coordinates the quorum. The physical presence requirement adds a real-world authorization layer that server-based quorum systems (which accept credentials from anywhere) cannot replicate. A server-based quorum is vulnerable to remote coercion; an in-person physical quorum is not.

**Technical constraint on iOS:** UWB multi-device proximity is pairwise (two devices at a time). The M-of-N ceremony therefore requires M sequential UWB sessions in a room setting (A↔B, A↔C, A↔D, etc.), each contributing one share to the coordinating device. This is practical for M≤5 in a room. CryptoKit does not include Shamir SSS natively, but a constant-time implementation over GF(2^8) or GF(prime) is straightforward to include. Reconstructed key material must be handled with care to avoid memory disclosure — use `Data` pinned to non-swappable memory or wipe immediately after use via `withUnsafeMutableBytes { memset }`.

---

## Summary Table

| Feature | Theme | Persona | iOS Constraint |
|---|---|---|---|
| Cryptographic Panic Wipe | Security | Journalist / Activist | Keychain delete (not SE delete) |
| P2P Basket Delivery via Wi-Fi Aware | File Transfer | Field Journalist / Offline User | iOS 26+ for Wi-Fi Aware; Multipeer fallback |
| Offline Travel Mode | Vault / Border Crossing | Journalist / Lawyer | Keychain key architecture |
| Hardware Key (YubiKey NFC) 2FA | Vault Access | Enterprise / Security Researcher | CoreNFC + Yubico SDK |
| Delay-Tolerant Proximity Outbox | File Transfer | Activist / Field User | BLE background limits; iOS 26 Wi-Fi Aware |
| Threshold-Gated Group Document (M-of-N) | Shared Secrets | Legal / Journalist Team | Sequential UWB sessions; manual Shamir impl |

---

## Research Notes & Caveats

- Direct API access to Reddit, discuss.privacyguides.net, hn.algolia.com, and freedom.press was blocked by network policy; community findings are based on indexed/cached content from web search.
- Competitor feature data is sourced from App Store listings, GitHub changelogs, and press coverage through April 2026.
- iOS 26 API details sourced from WWDC 2025 session recordings, Apple Developer Documentation, and NowSecure / ElcomSoft security research.
- Signal SPQR and Secure Backups features confirmed via aboutsignal.com and ghacks.net coverage.

---

*Report generated by automated scheduled task — Occulta Feature Discovery Research — April 30, 2026.*
