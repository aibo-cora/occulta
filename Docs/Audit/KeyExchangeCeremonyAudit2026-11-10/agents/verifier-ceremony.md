# v-ceremony verification result (repo at 87d9bf11, read-only, no builds)

Files read: Exchange+Manager.swift (all), KeyExchange.swift (all), PairingOffer.swift (all), PairwiseDerivation.swift (all),
Key+Manager.swift 340-395 and 1655-1925, Passphrase+Manager.swift, Data Models/Exchange.swift, Contact+Manager.swift 600-760,
Contact+Manager+Pairing.swift 100-123, KeyExchangeLiveView.swift 85-95, OccultaBundle.swift PrekeySyncBatch.

## KX-1  Words can be matched by a man in the middle: CONFIRMED-FROM-SOURCE (with preconditions the claim understated)

(a) No commitment on the attacker's side. Confirmed.
- The victim's nonce goes out in the discovery message at MC connect (Exchange+Manager.swift:507-514), in the clear, not as a hash. The comment at Key+Manager.swift:~1895 ("committed ... preventing a MITM from choosing nonces after seeing identity keys") describes the victim's own nonce only.
- The victim's identity + pairing field goes out at NI-fire + 3 s (806-810). The victim then waits (.waitingForPeerIdentity) and processes the peer identity whenever it comes (591-603).
- Nothing binds M's nonce, identity, pair keys or batch before M has seen the victim's. Nothing in the protocol hashes or commits a value before it is revealed.
- Extra freedom the claim missed: M's nonce is not frozen either. `self.peerNonce = nonce` (566-568) is overwritten on every discovery message with no status guard, until the payload is built (665/683/461). So M can vary its nonce (16 bytes) and does not need to touch the batch at all.
- The nonce route is the cheapest. It enters only the HKDF info (PairwiseDerivation.swift:~135, sortedNonces), not the extract, so the extract is done once. A trial is about 25-30 SHA-256 compressions (expand plus 5 word HMACs), about 1 us per core. 2^33 trials is a few core-hours per side and trivial on a GPU rack.
- Memory for the birthday table is about 2^32.3 entries (tens of GB), or none with distinguished-point collision search.
- Varying the batch (what the claim proposed) also works. Nothing in accepted() (PairingOffer.swift:162-181) constrains id, generatedAt or prekey ids. Only the digest being 32 bytes and the keys being on-curve P-256 points are checked.
- Save does not reject odd batches either: installPairingPrekeys uses `_ = try? bookkeeper.accept(...)` (Contact+Manager+Pairing.swift:113), so a failed accept does not fail the save.

(b) M as responder to both, and the processing order. Confirmed.
- Role is `myPeerID.displayName < peerID.displayName` (488). An MCPeerID display name is attacker-chosen text, so "Z..." sorts above any UUID. Both victims are then initiators and send first.
- An initiator accepts M's identity in .waitingForPeerIdentity or .sendingMyIdentity (591-593). The classical branch builds the payload (658-675) and `.confirming` follows about 6 s later.
- NI binding: the token is not tied to the MC peer. receivedDiscoveryTokens[token] = peerID takes whatever M sends (570); the NI match at 792 only looks up the dictionary. M relays B's real token to A and A's to B, so both real phones pass the 25 cm gate.
- Pinning: the advertiser accepts every invitation (915); securityIdentity is nil (182).
- Precondition the claim missed: M must beat the direct A-B connection into each phone's pin slot (479-487). A and B are adjacent and both advertise and browse, so A-B would normally connect first. This is a race. It is retryable (a failed race looks like an ordinary "Didn't connect"), so it is a probabilistic precondition, not a refutation.

(c) Every input to the words is computable by M. Confirmed.
- With a pairing: words = HKDF(ikm = pk || ik [|| sorted ML-KEM secrets], salt = identity XOR, info = domain + sorted nonces + transcript) (PairwiseDerivation.swift wordsKey).
  - pk = ECDH(M's agreement private, victim's agreement public): M holds its own private key.
  - ik = ECDH(M's identity private, victim's identity public). The identity salt is the XOR of the two public identity keys. M must use its own identity keys. A real contact key would deny M ik.
  - The transcript covers the two pair blocks (keys + batch digest). The ML-KEM key and ciphertexts are not in it.
- The victim's agreement key and identity key arrive only in the victim's identity message. So the search cannot start before both victims have sent identity.
- Words are 5 x (4 bytes mod 7776) from independent HMACs (Passphrase+Manager.swift:61-100), so 2^64.6, and the birthday cost is about 2^32.3 per side. The claim's figure is right.

(d) Timeouts. Mostly confirmed.
- The only timer is the 30 s NI-silence watchdog (286-300), reset on every NI update (777). There is no overall exchange timer and no timer on .confirming.
- While the real phones stay within range, NI updates keep arriving, so the victims wait.
- The practical limit is human patience: the victims sit in the live view while M computes. Minutes are plausible for a state attacker (GPU), hours are not.

(e) The confirmation screen. The claim needs this correction.
- The screen shows two hex fingerprints (KeyExchange.swift:165-167) but the instruction text asks to compare only the words (171).
- M cannot make the fingerprints match as well as the words. A's "PEER" row is H(M's key for A) and B's "MY" is H(B's real key), so they differ, and cross-comparing A.MY with B.PEER exposes the attack. M can only match them by sending A's real identity key to B. Then ik = ECDH(a, B) is unknown to M and M cannot evaluate the words.
- So a user who also cross-compares the fingerprints is protected. The UI does not ask for that. This is a real control, but only if users do something the screen does not request.

(f) acceptedPairing / PairingOffer.accepted does not constrain the varied fields (see (a)). It rejects only: off-curve points, a pair key equal to either identity or to our own pair keys, a bad digest size.

Hybrid path. Confirmed.
- M (responder) sends its ciphertext last (755-764 on the initiator side accepts it in .waitingForPeerQuantum or .sendingMyQuantum). Its ML-KEM secret is M's own Encaps output against the victim's key.
- That takes about 2^33 ML-KEM-1024 encapsulations (tens of us to 100 us each), so tens to a few hundred core-hours. It is feasible for a state actor but about 100x the classical-path cost.
- The words key ignores ciphertext bytes and uses only the secrets. M still has to learn both victims' ciphertexts first, so the stall comes after the ciphertext step.

Static-words fallback (no pairing, no ML-KEM). Confirmed at KeyExchange.swift:305 and Key+Manager.swift:~367.
- Words = f(ECDH(victim identity, M identity)), with no nonces, so M can precompute against known identity public keys.
- Correction: this path is reachable only when the victim's own makeOwnPairing succeeded and the peer's field is dropped. The screen then shows "Pair keys weren't exchanged..." (KeyExchange.swift:197), and on an existing pair-key contact save refuses (pairingWouldBeWeaker, Contact+Manager.swift:664).
- It is the documented Bug 196 "strip the pairing field" case, so it is partly known. The new part is that the words in this fallback are collision-searchable offline with no stall.

Test to settle: a harness with the two victim managers and a scripted M. Use a words function truncated to about 20 bits so the birthday search runs in a test. M varies its nonce in a second discovery message after receiving both identities. Assert that both sides get equal words and that peerNonce was overwritten after the first discovery. Also assert that a second discovery message does not change peerNonce (the proposed fix).

## KX-2  ML-KEM stripping: CONFIRMED-FROM-SOURCE

- A relay that drops `encapsulationKey` from both identity messages and passes everything else unchanged makes both phones take the classical branch (614-616 false, 649-697). Both set hybridResult nil.
- Words = wordsKey(pk, ik, nonces, transcript, mlkemSecrets nil) on both sides. They are equal because the relayed inputs are identical. The ML-KEM key and ciphertexts are not in the pair-block transcript (PairwiseDerivation.swift PairBlock.encoded: 0x02, agreement, signing, ML-DSA length and key, batch digest), and the words ikm adds ML-KEM secrets only when present.
- The only tell is the missing "Quantum-resistant exchange" label (KeyExchange.swift:188-192). Nothing else is shown.
- update(key:) (Contact+Manager.swift:625-744) refuses only a pair-key loss (pairingWouldBeWeaker, 664). Nothing compares the new key's quantumKeyMaterial with the current row's, so the new row is saved with quantumKeyMaterialEncrypted nil.
- Side effect: the contact silently stops being trustee-eligible (fetchTrusteeEligibleContacts keys on quantumKeyMaterialEncrypted != nil, Contact+Manager.swift:1710-1713).
- The relay still needs M in the path with the same pin-race precondition as KX-1. A pure relay learns no secret now (pk and ik need a private key). The loss is the ML-KEM layer, which matters for harvest-now-decrypt-later against the P-256-only pk/ik. The cost is an unrecorded design decision, not a break.
- I found no recorded decision for ML-KEM stripping (grep of Docs/Bugs and bugs.md found nothing). The Bug 196 doc covers `pairing` stripping only.

Test to settle: a two-manager loopback that clears `encapsulationKey` in both identity messages, then asserts both words equal and hybridResult nil. A second test should save over an existing hybrid contact and assert the row lost quantumKeyMaterial (this currently passes, i.e. no guard).

## KX-3  Teardown does not fence late callbacks: PARTLY (a, b, c, d each hold as stated; (a) and (b) are narrow, (c) is the most reachable)

(a) CONFIRMED. A latent crash, narrow window.
- handleSessionStateChange has `guard state == .connected` (475) and the pin guard (479) passes with connectedPeerID nil. Then 486-488 runs `self.multipeerSession!`.
- teardownSessions nils multipeerSession (254) and connectedPeerID (262). The delegate callback is re-dispatched via DispatchQueue.main.async (870-875), so a block queued before teardown still runs after it (`weak self` is still alive).
- The window is one main-queue hop, so it takes a `.connected` arriving at the instant of timeout, cancel or backgrounding.
- Related gap: the handler never checks the `session` parameter. After start() calls finish() and setupMC() builds a new session, a stale `.connected` from the old session can pin the new exchange to the old peer. The `!` is then not nil, so there is no crash, only a wrong pin.

(b) CONFIRMED. NISessionDelegate is not nil'd in teardown (only invalidate and `nearbySession = nil`, 240-242). A NI update block queued before teardown still calls handleNearbyObjectsUpdate, whose first line re-arms the 30 s watchdog (777), on a resting manager.
- 30 s later it sets phase = .timedOut and re-tears-down. If the view is still on screen, KeyExchange.onChange (118-127) shows the timeout banner and sets confirmingPayload = nil. After a successful save (`finish()` at 344) the verdict cover W-11 hangs off ConfirmationView; clearing confirmingPayload removes that view and therefore the cover, which the code says "can't be dismissed from outside" (276).
- Likelihood is low (a block must be queued at the exact `finish()`; NI updates are frequent while near).

(c) CONFIRMED. The most reachable.
- The classical Tasks at 668-675, 686-695 and 837-844 do `guard let self` and then set phase = .mlKemExchanged(payload) with no phase or exchangeStatus check. After finish() the Task still holds the captured payload and sets phase from .resting, and 3 s later .confirming(p). KeyExchange.onChange then shows ConfirmationView for an exchange with no sessions. Confirm then calls saveExchange with the captured payload (including pair keys and Enclave blobs).
- The hybrid paths are guarded: 467 requires phase == .mlKemExchanged, and 633-634 / 643-644 / 759-760 require exchangeStatus, which teardown nils.
- A real trigger: backgrounding the app in the live view calls finish() (KeyExchangeLiveView.swift:91) while the view stays up; so does a watchdog timeout. The classical path is the normal one on iOS 18.6-25 and with older peers.
- Impact: a cancelled exchange comes back and can be confirmed and saved. The other phone may have abandoned it, so one phone holds a pairing the other does not (lasting loss of a relationship, medium-low). If the view was dismissed, the manager is freed and the weak self guard makes it harmless.

(d) CONFIRMED but benign. receivedDiscoveryTokens is private(set) and is not cleared in teardownSessions (236-282) or anywhere else.
- Effect is nil in practice: each start() creates a new NISession with new tokens. A replayed old token would produce no NI updates.
- It is an in-memory residue of the previous peer's MCPeerID and token until the manager is freed. It is a hygiene note, not a vulnerability.

Tests to settle:
- (a) Construct the manager, set multipeerSession, call finish(), then drive session(_:didChange:.connected) through the delegate and flush the main queue. Expect no crash (it currently traps). A second test should deliver a `.connected` from a session other than the current one and assert the pin does not change.
- (b) Queue a NI update after finish() and assert no watchdog exists afterwards.
- (c) With a classical-path manager, deliver the peer identity, call finish() before 3 s, advance, and assert phase stays .resting.
- (d) Assert receivedDiscoveryTokens is empty after finish().

## Suggested fixes (not applied; read-only)
- KX-1: bind M's side. Have each phone send a hash commitment to its identity and pairing field (and nonce) in the discovery message and reveal it later, rejecting a mismatch and any second discovery message. Alternatively lengthen the words or add a short authentication string where the revealer is the party that spoke second.
- KX-2: put "encapsulationKey offered or absent" into the transcript, or show the hybrid state to both users and refuse (or warn on) a re-exchange that loses the ML-KEM material the contact already has.
- KX-3: replace the force-unwrap with a guard. Check the session parameter against self.multipeerSession. Fence every classical Task on exchangeStatus == .done and phase. Nil the NI delegate and clear the token dictionary in teardown.
