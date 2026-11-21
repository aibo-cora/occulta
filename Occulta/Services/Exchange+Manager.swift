//
//  Exchange+Manager.swift
//  Occulta
//
//  Sequential hybrid post-quantum key exchange.
//  Roles are determined at MC connect by comparing UUID display names —
//  lexicographically lower = initiator. Initiator sends first at every step;
//  responder waits and replies. Eliminates all parallel send races and the
//  MITM timing window present in the previous parallel design.
//
//  ⚠️ Backward compatibility contract:
//  - All messages use `version: .v1` on the wire.
//  - Classical (P-256-only) exchanges use hybridResult: nil in the Payload.
//  - If PostQuantumProvider is nil (iOS < 26), exchange is classical-only.
//  - If peer sends identity without `encapsulationKey`, exchange is classical-only.
//
//  Commit, then reveal (Bug 198): each phone's discovery message carries a hash of its nonce; the nonce goes out last,
//  initiator first, after every other message, and the words and the routing key are derived over both nonces and a hash
//  of every message of the exchange (`ExchangeCommitment`). A peer whose discovery message carries no commitment, a build
//  older than 2.0.5 or a relay that removed it, is refused before any key is exchanged: there is no uncommitted derivation.
//
//  ⚠️ Thread safety:
//  MC and NI delegate callbacks arrive on arbitrary background threads.
//  All state mutations are dispatched to the main queue via `DispatchQueue.main.async`.
//  Main queue is serial + FIFO, preserving MC's per-peer ordering guarantee.
//  This also ensures @Observable property changes are UI-safe.
//

import Foundation
import NearbyInteraction
import MultipeerConnectivity
import os
import OccultaCore
import OccultaFormats

@Observable
class ExchangeManager: NSObject {
    private var nearbySession: NISession?
    private var lastNIConfiguration: NINearbyPeerConfiguration?

    // Not `private`: peer-pinning tests construct the manager without going through
    // `start()` (which would trigger real Bluetooth advertising/browsing) and instead
    // set this directly, then drive state via the MCSessionDelegate conformance below.
    var multipeerSession: MCSession?
    private(set) var receivedDiscoveryTokens: [NIDiscoveryToken: MCPeerID] = [:]

    private let serviceType = "peer-data-ex"
    private let log = Logger(subsystem: "com.occulta.multipeer", category: "multipeer")

    private var watchdog: DispatchSourceTimer?

    /// Counts the exchanges that have ended. A callback or a task records the number when it is queued and does nothing if
    /// the number has moved when it runs: whatever was queued before `teardownSessions()` ran belongs to an exchange that
    /// is over, and must not touch the manager that follows (Bug 200). Read from the Multipeer and NearbyInteraction
    /// delegate threads as well as the main queue, so it is behind a lock.
    private let generationLock = OSAllocatedUnfairLock(initialState: 0)
    private var generation: Int { self.generationLock.withLock { $0 } }

    private var advertiser: MCNearbyServiceAdvertiser?
    private var browser: MCNearbyServiceBrowser?

    var isExchangePossible: Bool {
        NISession.deviceCapabilities.supportsPreciseDistanceMeasurement
    }

    // MARK: - Sequential protocol state

    /// Peer we connected to via MC. Identity/ciphertext from any other peer is rejected.
    private(set) var connectedPeerID: MCPeerID?
    /// True if our UUID display name sorts below the peer's — set once at MC connect.
    private var isInitiator: Bool = false
    /// Drives the sequential send/wait ordering for both identity and quantum phases.
    private var exchangeStatus: ExchangeStatus?
    /// Identity message that arrived before NI confirmed proximity (exchangeStatus was nil).
    /// Replayed immediately after NI fires and sets the initial status.
    private var bufferedIdentityMessage: (peerID: MCPeerID, data: Data)?

    // MARK: - PQ exchange state

    /// PQ provider — nil on iOS < 26.
    private let postQuantumProvider: PostQuantumProvider? = PostQuantumProviderFactory.create()
    /// Our 16-byte nonce, generated at session start. Its commitment goes out in discovery and the nonce itself last (Bug 198).
    private var ourNonce: Data?
    /// Peer's nonce, from its reveal once that has been checked against its commitment. Nil until then.
    private var peerNonce: Data?
    /// Opaque handle to our SE-backed ML-KEM-1024 private key.
    private var privateKeyHandle: Any?
    /// Peer's P-256 identity key — stored for hybrid result assembly.
    private var peerIdentity: Data?
    /// Our ML-KEM encapsulation key, included in the identity message.
    var encapsulationKeyData: Data?

    // MARK: - Commit, then reveal (Bug 198)

    /// What the peer committed to in its discovery message. An exchange goes no further without one: a peer that sends none,
    /// an older build or a relay that removed it, is refused (`ExchangePhase.peerNeedsUpdate`).
    private var peerCommitment: Data?
    /// Whether this exchange has had its one discovery message. A second never replaces the first one's nonce or commitment.
    private var peerDiscoveryAccepted = false
    /// Every message of the exchange before the reveal, as sent and as received: what the words and the routing key cover.
    private var transcriptMessages: [ExchangeCommitment.Message] = []
    /// Both nonces and the transcript, once the peer's reveal has been checked.
    private var committedExchange: ExchangePhase.Payload.Committed?
    /// True from the moment proximity starts the exchange until its last message: ranging does not reset the deadline of a
    /// step while it is.
    private var protocolInProgress = false
    private var stepDeadline: DispatchSourceTimer?

    /// How long a phone waits for the peer's next message before the exchange ends. Not reset by ranging updates: the two
    /// real phones keep ranging each other while a man in the middle takes his time.
    var stepTimeout: TimeInterval = 15
    /// The pause before each step the protocol takes on its own; the live view shows it as progress. A test shortens it.
    var stepDelay: Duration = .seconds(3)
    /// Our identity key as sent. A test supplies one that needs no Secure Enclave.
    var identityProvider: () throws -> Data = {
        let keyManager = Manager.Key()
        #if targetEnvironment(simulator)
        return keyManager.fixedX963
        #else
        return try keyManager.retrieveIdentity()
        #endif
    }
    #if DEBUG
    /// For tests: receives every message in place of the Multipeer session, and makes the discovery token a stand-in.
    var sendInterceptorForTesting: ((Data) throws -> Void)?
    #endif

    private var ourRole: ExchangeCommitment.Role { self.isInitiator ? .initiator : .responder }
    private var peerRole: ExchangeCommitment.Role { self.isInitiator ? .responder : .initiator }

    // MARK: - Routing key and first prekeys (`bugs.md` Bug 196)

    /// Our first prekeys: a scratch record with one pending batch, made when the peer connects and held in memory
    /// until `save()`. Nil if the Enclave couldn't make them, in which case no `pairing` field is sent and the pairing
    /// goes the way it did before.
    private(set) var ownPrekeys: PrekeyRecord?
    /// Our pair keys, made with the prekeys: both or neither, because a phone sends all of the `pairing` field or none.
    private(set) var ownPairKeys: PairingOffer.OwnPairKeys?
    /// The `pairing` field we send, made once with the keys. Its batch is read back from the Enclave blobs one time, so the
    /// batch sent and the digest of it in the transcript are the same evaluation and cannot differ.
    private(set) var ownPairingField: Exchange.PairingField?
    /// Makes our pair keys. The Enclave in production; a test injects software keys.
    var pairKeyProvider: any CardKeyProviding = EnclaveCardKeys()
    /// Makes our first prekeys. The Enclave in production; a test injects a record that needs none.
    var prekeyMaker: () throws -> PrekeyRecord = { try PairingOffer.makeOwnPrekeys() }
    /// What the peer's `pairing` field came to once validated, and the pair-key ECDH with it. Nil from a phone that can't
    /// hold a routing key, or whose field we can't use.
    private var peerPairing: (batch: PairingOffer.Batch, keys: PairingOffer.PeerPairKeys, ecdh: Data)?

    // MARK: - Card meeting check (SPEC §7)

    /// What the contact's card field lets us sign and check; set by the caller when the exchange starts from a
    /// contact (`start(cardMeeting:)`). `.none` for an exchange with no card conversation.
    var cardMeeting: CardMeetingContext = .none
    /// The identity key we sent, which the proof is bound to.
    private var ourSentIdentity: Data?
    /// The peer's proof message, kept for `cardMeetingVerdict(for:)`.
    private(set) var peerCardProof: Data?

    // MARK: - Exchange status state machine

    private struct QuantumPayload {
        let secret: Data
        let ciphertext: Data
    }

    private enum ExchangeStatus {
        /// About to send our identity. `ours` is pre-computed only for the responder —
        /// who encapsulates the initiator's ML-KEM key upon receiving their identity,
        /// before sending back their own.
        case sendingMyIdentity(ours: QuantumPayload?)
        /// Sent our identity; waiting for the peer's.
        case waitingForPeerIdentity
        /// About to send our ML-KEM ciphertext. `theirs` is set only for the responder —
        /// who already decapsulated the initiator's ciphertext before sending theirs.
        case sendingMyQuantum(ours: QuantumPayload, theirs: QuantumPayload?)
        /// Sent our ciphertext; waiting for the peer's.
        case waitingForPeerQuantum(ours: QuantumPayload)
        /// Both ciphertexts exchanged — ready to assemble the final result.
        case complete(ours: QuantumPayload, theirs: QuantumPayload)
        /// Every message but the nonces is in; the initiator has revealed its nonce, the responder waits for it. `hybrid` is
        /// nil for a classical exchange.
        case awaitingReveal(hybrid: (ours: QuantumPayload, theirs: QuantumPayload)?)
        /// Terminal state for classical-only exchanges; prevents re-processing stray messages.
        case done

    }

    // MARK: - Result type

    struct HybridExchangeResult: Equatable {
        let peerP256PublicKey: Data
        let mlkemSecret1: Data
        let mlkemSecret2: Data
        let ourNonce: Data
        let peerNonce: Data
        let ourCiphertext: Data
        let peerCiphertext: Data
    }

    // MARK: - Exchange phase

    enum ExchangePhase: Equatable {
        case resting
        case searching
        case found
        case connected
        case identityExchanged(fingerprint: Data)
        case mlKemExchanged(Payload)
        case confirming(Payload)
        case complete
        case timedOut
        case failed
        /// The peer's discovery message carried no commitment to its nonce: a phone on a version older than 2.0.5, or a relay
        /// that removed it. Nothing was saved. The screen says the other phone needs to update, whatever the cause, since a
        /// phone cannot tell the two apart.
        case peerNeedsUpdate

        struct Payload: Equatable {
            let fingerprint: Data
            let classicalKey: Data
            let hybridResult: HybridExchangeResult?
            /// Set when both phones sent a `pairing` field: the routing key, pair keys and first prekeys follow from it.
            var pairing: PairingOffer? = nil
            /// Whether we sent one ourselves. With `pairing` nil it means the peer sent none we could use, which the
            /// confirmation screen says.
            var offeredPairing: Bool = false
            /// Both phones committed to their nonces and revealed them, and the words and the routing key cover every message
            /// of the exchange (Bug 198). An exchange with no commitment from the peer never gets this far.
            let committed: Committed
            /// Whether we sent an ML-KEM key ourselves. With `hybridResult` nil it means none came back, which the screen
            /// says (Bug 199).
            var offeredQuantum: Bool = false

            /// What a committed exchange's words and routing key are derived over.
            struct Committed: Equatable {
                let ourNonce: Data
                let peerNonce: Data
                /// `ExchangeCommitment.transcript` of the messages before the reveal.
                let transcript: Data
            }
        }
    }

    var phase: ExchangePhase = .resting
    var distance: Float? = nil
    var direction: SIMD3<Float>? = nil

    override init() {
        super.init()
    }

    private func setupMC() {
        let peerID = MCPeerID(displayName: UUID().uuidString)

        self.multipeerSession = MCSession(peer: peerID, securityIdentity: nil, encryptionPreference: .required)
        self.multipeerSession?.delegate = self

        self.advertiser = MCNearbyServiceAdvertiser(peer: peerID, discoveryInfo: nil, serviceType: self.serviceType)
        self.browser = MCNearbyServiceBrowser(peer: peerID, serviceType: self.serviceType)

        self.advertiser?.delegate = self
        self.browser?.delegate = self
    }

    func start(cardMeeting: CardMeetingContext = .none) {
        self.finish()
        self.cardMeeting = cardMeeting

        // No nonce, nothing to commit to: the exchange does not start.
        guard let nonce = Manager.Key().generateExchangeNonce() else {
            self.phase = .failed
            return
        }
        self.ourNonce = nonce

        self.nearbySession = NISession()
        self.nearbySession?.delegate = self

        self.setupMC()

        if let provider = self.postQuantumProvider, let keyPair = provider.generateKeyPair() {
            self.privateKeyHandle = keyPair.privateKeyHandle
            self.encapsulationKeyData = keyPair.publicKeyData
            #if DEBUG
            debugPrint("[KE] ML-KEM keypair generated (\(self.encapsulationKeyData?.count ?? 0) bytes)")
            #endif
        }

        self.phase = .searching

        let generation = self.generation
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(3))
            guard let self, self.generation == generation, case .searching = self.phase else { return }
            self.advertiser?.startAdvertisingPeer()
            self.browser?.startBrowsingForPeers()
            self.scheduleWatchdog()
            #if DEBUG
            debugPrint("[KE] Advertising and browsing started")
            #endif
        }
    }

    func finish() {
        self.teardownSessions()
        // The card's signing blob and the peer's key go with the exchange, not with the view holding the manager.
        self.cardMeeting = .none
        self.phase = .resting
    }

    func confirm() {
        self.phase = .complete
    }

    #if DEBUG
    /// For tests, which can't have NearbyInteraction confirm proximity: the state the exchange is in once it has, waiting
    /// for the peer's identity.
    func waitForPeerIdentityForTesting() { self.exchangeStatus = .waitingForPeerIdentity }

    /// For tests: whether the 30-second watchdog is armed.
    var isWatchdogArmed: Bool { self.watchdog != nil }

    /// For tests: the ML-KEM key pair `start()` makes, without the radios.
    func preparePostQuantumForTesting() {
        guard let keyPair = self.postQuantumProvider?.generateKeyPair() else { return }
        self.privateKeyHandle = keyPair.privateKeyHandle
        self.encapsulationKeyData = keyPair.publicKeyData
    }

    /// For tests: whether the initiator holds its ciphertext, about to send it.
    var isSendingMyQuantum: Bool {
        if case .sendingMyQuantum = self.exchangeStatus { return true }
        return false
    }

    /// For tests: the nonce `start()` makes, without the radios.
    func prepareNonceForTesting(_ nonce: Data) { self.ourNonce = nonce }

    /// For tests: what the peer's discovery message came to.
    var peerNonceForTesting: Data? { self.peerNonce }
    var peerCommitmentForTesting: Data? { self.peerCommitment }

    /// For tests: whether a step deadline is running, and how many times one has been armed or moved.
    var isStepDeadlineArmed: Bool { self.stepDeadline != nil }
    private(set) var stepDeadlineArmCountForTesting = 0
    #endif

    private func teardownSessions() {
        // First: from here on, everything queued for this exchange is stale.
        self.generationLock.withLock { $0 &+= 1 }

        self.watchdog?.cancel()
        self.watchdog = nil
        self.stepDeadline?.cancel()
        self.stepDeadline = nil
        self.protocolInProgress = false

        self.nearbySession?.delegate = nil
        self.nearbySession?.invalidate()
        self.nearbySession = nil
        self.lastNIConfiguration = nil

        self.advertiser?.stopAdvertisingPeer()
        self.advertiser?.delegate = nil
        self.advertiser = nil

        self.browser?.stopBrowsingForPeers()
        self.browser?.delegate = nil
        self.browser = nil

        self.multipeerSession?.disconnect()
        self.multipeerSession?.delegate = nil
        self.multipeerSession = nil

        // ⚠️ Release SE-backed ML-KEM private key handle.
        // For SecureEnclave.MLKEM1024, releasing the reference means the SE key
        // can no longer be used. No explicit SE delete needed — CryptoKit SE keys
        // are accessed via their object reference, not a keychain tag.
        self.privateKeyHandle = nil

        self.receivedDiscoveryTokens = [:]
        self.connectedPeerID = nil
        self.isInitiator = false
        self.exchangeStatus = nil
        self.bufferedIdentityMessage = nil
        self.ourNonce = nil
        self.peerNonce = nil
        self.peerCommitment = nil
        self.peerDiscoveryAccepted = false
        self.transcriptMessages = []
        self.committedExchange = nil
        self.peerIdentity = nil
        self.ownPrekeys = nil
        self.ownPairKeys = nil
        self.ownPairingField = nil
        self.peerPairing = nil
        self.ourSentIdentity = nil
        self.peerCardProof = nil
        self.encapsulationKeyData = nil
        self.distance = nil
        self.direction = nil

        #if DEBUG
        debugPrint("[KE] Exchange sessions torn down")
        #endif
    }

    // MARK: - Watchdog

    private func scheduleWatchdog() {
        self.watchdog?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + 30)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            #if DEBUG
            debugPrint("[KE] Watchdog fired — no NI updates in 30s")
            #endif
            self.phase = .timedOut
            self.teardownSessions()
        }
        timer.resume()
        self.watchdog = timer
    }

    // MARK: - Step deadline (Bug 198)

    /// Once the exchange has started, the next message has to arrive within `stepTimeout`, and a ranging update does not
    /// move that. Called whenever a step completes, in either direction.
    private func armStepDeadline() {
        #if DEBUG
        self.stepDeadlineArmCountForTesting += 1
        #endif
        self.watchdog?.cancel()
        self.watchdog = nil
        self.stepDeadline?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + self.stepTimeout)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            #if DEBUG
            debugPrint("[KE] Step deadline passed — no message in \(self.stepTimeout)s")
            #endif
            self.phase = .timedOut
            self.teardownSessions()
        }
        timer.resume()
        self.stepDeadline = timer
    }

    private func stepProgress() {
        guard self.protocolInProgress else { return }
        self.armStepDeadline()
    }

    /// The last message of the exchange is in: the deadline gives way to the watchdog the confirmation screen has always had.
    private func endProtocolSteps() {
        guard self.protocolInProgress else { return }
        self.protocolInProgress = false
        self.stepDeadline?.cancel()
        self.stepDeadline = nil
        self.scheduleWatchdog()
    }

    // MARK: - Send helpers

    /// Sends one message and, for a step the transcript covers, records exactly the bytes that went out.
    private func transmit(_ exchange: Exchange, to peerID: MCPeerID, recording step: ExchangeCommitment.Step? = nil) throws {
        let encoded = try JSONEncoder().encode(exchange)
        #if DEBUG
        if let hook = self.sendInterceptorForTesting {
            try hook(encoded)
        } else {
            guard let session = self.multipeerSession else { throw CocoaError(.fileNoSuchFile) }
            try session.send(encoded, toPeers: [peerID], with: .reliable)
        }
        #else
        guard let session = self.multipeerSession else { throw CocoaError(.fileNoSuchFile) }
        try session.send(encoded, toPeers: [peerID], with: .reliable)
        #endif
        if let step { self.record(step, by: self.ourRole, encoded) }
    }

    /// Adds a message to the transcript. The first message of a step and role is the one that counts: a message the peer
    /// ignores as a second one never reaches the transcript on its side.
    private func record(_ step: ExchangeCommitment.Step, by role: ExchangeCommitment.Role, _ bytes: Data) {
        guard !self.transcriptMessages.contains(where: { $0.step == step && $0.role == role }) else { return }
        self.transcriptMessages.append(ExchangeCommitment.Message(role: role, step: step, bytes: bytes))
    }

    /// Our NearbyInteraction token as it goes in a message. Nil while the session has none.
    private func archivedDiscoveryToken() throws -> Data? {
        #if DEBUG
        if self.sendInterceptorForTesting != nil { return Data([0x01]) }
        #endif
        guard let token = self.nearbySession?.discoveryToken else { return nil }
        return try NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: true)
    }

    /// A message we could not send ends the exchange: the peer would wait for it until its deadline, and nothing here may go on to
    /// a step that assumes it went out. The phase is the one a failed exchange has, so the screen says it did not check out.
    private func sendFailed() {
        self.phase = .failed
        self.teardownSessions()
    }

    /// - Returns: whether the message went out. When it did not the exchange has ended (`sendFailed`).
    private func sendIdentity(to peerID: MCPeerID) -> Bool {
        do {
            guard let archivedToken = try self.archivedDiscoveryToken() else { self.sendFailed(); return false }
            let keyingMaterial = try self.identityProvider()
            self.ourSentIdentity = keyingMaterial
            let exchange = Exchange(
                id: UUID().uuidString,
                token: archivedToken,
                version: .v1,
                identity: keyingMaterial,
                encapsulationKey: self.encapsulationKeyData,
                pairing: self.ownPairingField
            )
            try self.transmit(exchange, to: peerID, recording: .identity)
            self.stepProgress()
            #if DEBUG
            debugPrint("[KE] Identity sent to \(peerID.displayName)")
            #endif
            return true
        } catch {
            #if DEBUG
            debugPrint("[KE] Identity send failed: \(error)")
            #endif
            self.sendFailed()
            return false
        }
    }

    /// - Returns: whether the message went out. When it did not the exchange has ended (`sendFailed`).
    private func sendCiphertext(_ ciphertext: Data, to peerID: MCPeerID) -> Bool {
        do {
            guard let archivedToken = try self.archivedDiscoveryToken() else { self.sendFailed(); return false }
            let exchange = Exchange(
                id: UUID().uuidString,
                token: archivedToken,
                version: .v1,
                ciphertext: ciphertext
            )
            try self.transmit(exchange, to: peerID, recording: .ciphertext)
            self.stepProgress()
            #if DEBUG
            debugPrint("[KE] Ciphertext sent to \(peerID.displayName)")
            #endif
            return true
        } catch {
            #if DEBUG
            debugPrint("[KE] Ciphertext send failed: \(error)")
            #endif
            self.sendFailed()
            return false
        }
    }

    /// Our nonce, the last thing we send (Bug 198).
    ///
    /// - Returns: whether the message went out. When it did not the exchange has ended (`sendFailed`).
    private func sendReveal(to peerID: MCPeerID) -> Bool {
        guard let ourNonce else { self.sendFailed(); return false }
        do {
            try self.transmit(Exchange(id: UUID().uuidString, token: Data(), version: .v1, revealedNonce: ourNonce), to: peerID)
            self.stepProgress()
            return true
        } catch {
            #if DEBUG
            debugPrint("[KE] Reveal send failed: \(error)")
            #endif
            self.sendFailed()
            return false
        }
    }

    /// The meeting-check proof (SPEC §7), sent once the ML-KEM step completes: a signature by the card signing key
    /// over the transcript whenever the field holds one, else 64 random bytes. Always `CardMeeting.proofByteCount`
    /// long, in an `Exchange` with an empty token, so nothing shows which it is.
    private func sendCardProof(for result: HybridExchangeResult) {
        guard let peerID = self.connectedPeerID, let ourIdentity = self.ourSentIdentity else { return }
        let transcript = CardMeeting.transcript(
            identityKeys: (ourIdentity, result.peerP256PublicKey),
            nonces: (result.ourNonce, result.peerNonce),
            mlkemCiphertexts: (result.ourCiphertext, result.peerCiphertext)
        )
        let signed = try? self.cardMeeting.sign?(CardMeeting.proofPayload(transcript: transcript, signerIdentityKey: ourIdentity))
        let proof = signed.flatMap { $0.count == CardMeeting.proofByteCount ? $0 : nil } ?? CardMeeting.filler()
        do {
            try self.transmit(Exchange(id: UUID().uuidString, token: Data(), version: .v1, cardProof: proof), to: peerID)
        } catch {
            #if DEBUG
            debugPrint("[KE] Card proof send failed: \(error)")
            #endif
        }
    }

    /// The meeting-check verdict for a completed exchange (`payload` is the one `.confirming` carries). Final once
    /// the peer's proof message has arrived, which is long before the confirmation screen is. Call it after the
    /// ceremony's own confirmation succeeds and before `finish()`, which discards the proof. `.none` wherever SPEC §7
    /// shows nothing; W-11 for a classical-only exchange where it shows a verdict (Bug 203).
    func cardMeetingVerdict(for payload: ExchangePhase.Payload) -> CardMeetingVerdict {
        CardMeetingContext.verdict(
            context: self.cardMeeting, result: payload.hybridResult, offeredQuantum: payload.offeredQuantum,
            ourIdentity: self.ourSentIdentity, peerProof: self.peerCardProof
        )
    }

    // MARK: - Our prekeys and pair keys, and the peer's

    /// Our first prekeys and our pair keys, once, for the peer we're pinned to. Both or neither: a phone sends all of the
    /// `pairing` field or none, so a failure making either sends none and the pairing goes the way it did before.
    func makeOwnPairing() {
        guard self.ownPrekeys == nil else { return }
        guard
            let prekeys = try? self.prekeyMaker(), let keys = try? PairingOffer.makeOwnPairKeys(using: self.pairKeyProvider),
            let field = PairingOffer.field(prekeys: prekeys, keys: keys)
        else {
            self.ownPrekeys = nil
            self.ownPairKeys = nil
            self.ownPairingField = nil
            return
        }
        self.ownPrekeys = prekeys
        self.ownPairKeys = keys
        self.ownPairingField = field
    }

    /// The peer's `pairing` field once validated, with the pair-key ECDH made from it. Nil if we sent none, the peer sent
    /// none, or it is not one we can use: the pairing is then made without pair keys.
    func acceptedPairing(
        _ field: Exchange.PairingField?, peerIdentity: Data
    ) -> (batch: PairingOffer.Batch, keys: PairingOffer.PeerPairKeys, ecdh: Data)? {
        guard let field, let ours = self.ownPairKeys else { return nil }
        let ourIdentity = self.ourSentIdentity ?? (try? self.identityProvider())
        guard
            let accepted = PairingOffer.accepted(field, ours: ours, ourIdentity: ourIdentity, peerIdentity: peerIdentity),
            let ecdh = try? PairingOffer.pairwiseECDH(ours: ours, peerAgreementKey: accepted.keys.agreementKey, using: self.pairKeyProvider)
        else { return nil }
        return (accepted.batch, accepted.keys, ecdh)
    }

    // MARK: - Final assembly

    /// The pairing offer for a payload built now: only when both phones sent a `pairing` field and both nonces are known.
    /// Anything missing means the peer can't hold a routing key, and the pairing is made without one.
    private func pairingOffer() -> PairingOffer? {
        guard
            let ourNonce, let peerNonce, let ownPrekeys, let ownPairKeys, let ownPairingField, let peerPairing,
            let exchangeTranscript = self.committedExchange?.transcript
        else { return nil }
        return PairingOffer(
            ourNonce: ourNonce, peerNonce: peerNonce, ownPrekeys: ownPrekeys,
            peerBatch: peerPairing.batch,
            ours: ownPairKeys, theirs: peerPairing.keys, pairwiseECDH: peerPairing.ecdh,
            exchangeTranscript: exchangeTranscript
        )
    }

    /// Both ciphertexts are in: every message but the nonces has been exchanged, and the reveal comes next.
    private func assembleHybridResult(ours: QuantumPayload, theirs: QuantumPayload) {
        guard let peerID = self.connectedPeerID else { return }
        self.startReveal(to: peerID, hybrid: (ours, theirs))
    }

    // MARK: - Reveal (Bug 198)

    /// Every message but the nonces is in. The initiator reveals its nonce now; the responder waits for it and reveals its
    /// own in answer, so each phone has fixed everything it sent before it learns the other's nonce.
    private func startReveal(to peerID: MCPeerID, hybrid: (ours: QuantumPayload, theirs: QuantumPayload)?) {
        self.exchangeStatus = .awaitingReveal(hybrid: hybrid)
        if self.isInitiator { guard self.sendReveal(to: peerID) else { return } }
        self.stepProgress()
    }

    /// The peer's nonce has opened its commitment: the exchange's words and routing key can be derived. Builds the payload
    /// the confirmation screen takes, from the same messages the peer holds.
    private func concludeCommitted(hybrid: (ours: QuantumPayload, theirs: QuantumPayload)?) {
        guard let ourNonce, let peerNonce, let peerIdentity,
              let transcript = ExchangeCommitment.transcript(self.transcriptMessages)
        else {
            self.phase = .failed
            self.teardownSessions()
            return
        }
        let committed = ExchangePhase.Payload.Committed(ourNonce: ourNonce, peerNonce: peerNonce, transcript: transcript)
        self.committedExchange = committed
        if let hybrid { self.exchangeStatus = .complete(ours: hybrid.ours, theirs: hybrid.theirs) } else { self.exchangeStatus = .done }
        self.endProtocolSteps()

        let result = hybrid.map {
            HybridExchangeResult(
                peerP256PublicKey: peerIdentity, mlkemSecret1: $0.ours.secret, mlkemSecret2: $0.theirs.secret,
                ourNonce: ourNonce, peerNonce: peerNonce, ourCiphertext: $0.ours.ciphertext, peerCiphertext: $0.theirs.ciphertext
            )
        }
        if let result { self.sendCardProof(for: result) }

        let payload = ExchangePhase.Payload(
            fingerprint: peerIdentity.sha256,
            classicalKey: peerIdentity,
            hybridResult: result,
            pairing: self.pairingOffer(),
            offeredPairing: self.ownPairKeys != nil,
            committed: committed,
            offeredQuantum: self.encapsulationKeyData != nil
        )
        self.phase = .mlKemExchanged(payload)
        let generation = self.generation
        let delay = self.stepDelay
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: delay)
            guard let self, self.generation == generation, case .mlKemExchanged(let p) = self.phase else { return }
            self.phase = .confirming(p)
        }
    }

    // MARK: - Phase handlers (always called on main queue)

    private func handleSessionStateChange(peerID: MCPeerID, state: MCSessionState) {
        guard state == .connected, let session = self.multipeerSession else { return }

        // Pin to the first peer only — a second peer connecting mid-exchange must not
        // hijack the slot the MITM guard below checks against.
        if let pinned = self.connectedPeerID, pinned != peerID {
            #if DEBUG
            debugPrint("[KE] Ignoring connection from second peer \(peerID.displayName) — already pinned to \(pinned.displayName)")
            #endif
            return
        }

        self.phase = .found
        self.connectedPeerID = peerID
        self.isInitiator = session.myPeerID.displayName < peerID.displayName

        // Our first prekeys, once, for the peer we're pinned to. Made here and not at `start()` so an exchange that
        // never finds anyone makes none. A failure sends no batch.
        self.makeOwnPairing()

        #if DEBUG
        debugPrint("[KE] MC connected: \(peerID.displayName) — role: \(self.isInitiator ? "initiator" : "responder")")
        #endif

        // One discovery message per exchange, with the commitment to our nonce and not the nonce (Bug 198).
        guard !self.transcriptMessages.contains(where: { $0.step == .discovery && $0.role == self.ourRole }) else { return }

        do {
            guard let archivedToken = try self.archivedDiscoveryToken() else {
                #if DEBUG
                debugPrint("[KE] Discovery token unavailable — NI session not ready")
                #endif
                return
            }
            let exchange = Exchange(
                id: UUID().uuidString,
                token: archivedToken,
                version: .v1,
                nonceCommitment: self.ourNonce.flatMap { ExchangeCommitment.commitment(to: $0) }
            )
            try self.transmit(exchange, to: peerID, recording: .discovery)
            #if DEBUG
            debugPrint("[KE] Discovery token sent to \(peerID.displayName)")
            #endif
        } catch {
            #if DEBUG
            debugPrint("[KE] Discovery send failed: \(error)")
            #endif
        }
    }

    /// The peer's one discovery message of this exchange, which has to carry its commitment to its nonce. A second discovery
    /// message changes nothing, so a man in the middle can neither swap a nonce after seeing our messages nor change what the
    /// commitment bound (Bug 198).
    ///
    /// A discovery message without a commitment ends the exchange before any key is exchanged or saved: it is from a phone on
    /// a version older than 2.0.5, or a relay removed the commitment, and a phone cannot tell which. Either way the words would
    /// not protect the exchange, so there is no derivation to fall back to. The phase is the same whatever the cause, and
    /// nothing here reads a depth. Not `private`: tests drive it without a NearbyInteraction token.
    ///
    /// - Returns: whether this was the exchange's discovery message and it committed.
    @discardableResult
    func handleDiscovery(_ decoded: Exchange, data: Data, from peerID: MCPeerID) -> Bool {
        guard peerID == self.connectedPeerID, !self.peerDiscoveryAccepted else { return false }
        self.peerDiscoveryAccepted = true

        guard let commitment = decoded.nonceCommitment, commitment.count == ExchangeCommitment.commitmentSize else {
            #if DEBUG
            debugPrint("[KE] Discovery without a commitment — exchange refused")
            #endif
            self.phase = .peerNeedsUpdate
            self.teardownSessions()
            return false
        }
        self.peerCommitment = commitment
        self.record(.discovery, by: self.peerRole, data)
        return true
    }

    /// Not `private`, like `multipeerSession` above: the decoder-fuzzing tests call it directly, on the main thread, since the
    /// delegate's `session(_:didReceive:fromPeer:)` only hops to the main queue and then calls this.
    func handleReceivedData(_ data: Data, from peerID: MCPeerID) {
        do {
            let decoded = try BoundedJSON.decode(Exchange.self, from: data)
            let delay = self.stepDelay

            // MARK: Meeting-check proof (before discovery: it has no identity and no ciphertext either)

            if decoded.isCardProof {
                guard peerID == self.connectedPeerID else { return }
                if self.peerCardProof == nil, let proof = decoded.cardProof, proof.count == CardMeeting.proofByteCount {
                    self.peerCardProof = proof
                }
                return
            }

            // MARK: Reveal — the peer's nonce, checked against what it committed to (Bug 198)

            if decoded.isNonceReveal {
                guard peerID == self.connectedPeerID, let commitment = self.peerCommitment,
                      case .awaitingReveal(let hybrid) = self.exchangeStatus,
                      let nonce = decoded.revealedNonce, nonce.count == ExchangeCommitment.nonceSize else { return }

                // A nonce that does not open the commitment, or is our own reflected back, ends the exchange.
                guard nonce != self.ourNonce, ExchangeCommitment.opens(commitment, with: nonce) else {
                    #if DEBUG
                    debugPrint("[KE] Revealed nonce does not match its commitment — exchange failed")
                    #endif
                    self.phase = .failed
                    self.teardownSessions()
                    return
                }
                self.peerNonce = nonce
                // The responder reveals in answer, so the initiator's is the first nonce that is known to anyone.
                if !self.isInitiator { guard self.sendReveal(to: peerID) else { return } }
                self.concludeCommitted(hybrid: hybrid)
                return
            }

            // MARK: Phase 1 — Discovery (token + commitment to the nonce)

            if decoded.isDiscovery {
                guard peerID == self.connectedPeerID else {
                    #if DEBUG
                    debugPrint("[KE] MITM guard: discovery from unexpected peer \(peerID.displayName)")
                    #endif
                    return
                }
                let token: NIDiscoveryToken
                do {
                    guard let unarchived = try NSKeyedUnarchiver.unarchivedObject(
                        ofClass: NIDiscoveryToken.self, from: decoded.token
                    ) else {
                        #if DEBUG
                        debugPrint("[KE] Discovery: token unarchive returned nil")
                        #endif
                        return
                    }
                    token = unarchived
                } catch {
                    #if DEBUG
                    debugPrint("[KE] Discovery: token unarchive threw: \(error)")
                    #endif
                    return
                }

                // One discovery message per exchange, and it has to carry a commitment: a second one neither replaces the
                // commitment nor re-points ranging, and one without a commitment ends the exchange.
                guard self.handleDiscovery(decoded, data: data, from: peerID) else { return }

                self.receivedDiscoveryTokens[token] = peerID

                #if DEBUG
                debugPrint("[KE] Discovery token received from \(peerID.displayName)")
                #endif

                let configuration = NINearbyPeerConfiguration(peerToken: token)
                self.lastNIConfiguration = configuration
                self.nearbySession?.run(configuration)
                return
            }

            // MARK: Phase 2 — Identity (P-256 + optional ML-KEM encapsulation key)

            if decoded.isIdentity {
                guard peerID == self.connectedPeerID else {
                    #if DEBUG
                    debugPrint("[KE] MITM guard: identity from unexpected peer \(peerID.displayName)")
                    #endif
                    return
                }
                switch self.exchangeStatus {
                case .waitingForPeerIdentity:
                    break
                case nil:
                    // NI hasn't confirmed proximity yet — buffer and replay when it does.
                    self.bufferedIdentityMessage = (peerID: peerID, data: data)
                    return
                default:
                    #if DEBUG
                    debugPrint("[KE] Identity received but not waiting — ignoring")
                    #endif
                    return
                }
                guard let peersP256Key = decoded.identity, peersP256Key.count == 65 else { return }

                // One identity message per exchange, only once the peer has committed to its nonce, and only while waiting for
                // it. Nothing replaces it, so the transcript holds the one the words were derived from (Bug 198).
                guard self.peerCommitment != nil, self.peerIdentity == nil else { return }

                #if DEBUG
                debugPrint("[KE] Identity received from \(peerID.displayName) — encapsulationKey: \(decoded.encapsulationKey != nil)")
                #endif

                self.record(.identity, by: self.peerRole, data)
                self.stepProgress()
                self.peerIdentity = peersP256Key
                self.peerPairing = self.acceptedPairing(decoded.pairing, peerIdentity: peersP256Key)
                self.phase = .identityExchanged(fingerprint: peersP256Key.sha256)

                if let peerEncapKey = decoded.encapsulationKey,
                   let provider = self.postQuantumProvider,
                   self.privateKeyHandle != nil {
                    // PQ path
                    #if DEBUG
                    debugPrint("[KE] PQ path — encapsulating peer's ML-KEM key")
                    #endif
                    guard let result = provider.encapsulate(peerPublicKeyData: peerEncapKey) else { return }
                    let ours = QuantumPayload(secret: result.sharedSecret, ciphertext: result.ciphertext)

                    if self.isInitiator {
                        // Received responder's identity → send our ciphertext.
                        self.exchangeStatus = .sendingMyQuantum(ours: ours, theirs: nil)
                        let generation = self.generation
                        Task { @MainActor [weak self] in
                            try? await Task.sleep(for: delay)
                            guard let self, self.generation == generation,
                                  case .sendingMyQuantum(let ours, _) = self.exchangeStatus else { return }
                            guard self.sendCiphertext(ours.ciphertext, to: peerID) else { return }
                            self.exchangeStatus = .waitingForPeerQuantum(ours: ours)
                        }
                    } else {
                        // Received initiator's identity → send our identity (quantum pre-computed).
                        self.exchangeStatus = .sendingMyIdentity(ours: ours)
                        let generation = self.generation
                        Task { @MainActor [weak self] in
                            try? await Task.sleep(for: delay)
                            guard let self, self.generation == generation,
                                  case .sendingMyIdentity(let ours?) = self.exchangeStatus else { return }
                            guard self.sendIdentity(to: peerID) else { return }
                            self.exchangeStatus = .waitingForPeerQuantum(ours: ours)
                        }
                    }
                } else {
                    // Classical fallback: no PQ provider, no private key, or peer has no encapsulation key.
                    #if DEBUG
                    debugPrint("[KE] Classical path — provider: \(self.postQuantumProvider != nil), privateKey: \(self.privateKeyHandle != nil), peerKey: \(decoded.encapsulationKey != nil)")
                    #endif

                    // The classical exchange: this identity message is the last before the reveal.
                    if self.isInitiator {
                        self.startReveal(to: peerID, hybrid: nil)
                    } else {
                        self.exchangeStatus = .sendingMyIdentity(ours: nil)
                        let generation = self.generation
                        Task { @MainActor [weak self] in
                            try? await Task.sleep(for: delay)
                            guard let self, self.generation == generation, case .sendingMyIdentity = self.exchangeStatus else { return }
                            guard self.sendIdentity(to: peerID) else { return }
                            self.startReveal(to: peerID, hybrid: nil)
                        }
                    }
                }
                return
            }

            // MARK: Phase 3 — Ciphertext (ML-KEM ciphertext for decapsulation)

            if decoded.isCiphertext {
                guard peerID == self.connectedPeerID else {
                    #if DEBUG
                    debugPrint("[KE] MITM guard: ciphertext from unexpected peer \(peerID.displayName)")
                    #endif
                    return
                }
                guard self.peerCommitment != nil, case .waitingForPeerQuantum(let ours) = self.exchangeStatus else {
                    #if DEBUG
                    debugPrint("[KE] Ciphertext received but not waiting — ignoring")
                    #endif
                    return
                }
                guard let ciphertext = decoded.ciphertext,
                      let handle = self.privateKeyHandle,
                      let provider = self.postQuantumProvider else { return }

                #if DEBUG
                debugPrint("[KE] Peer's ciphertext received from \(peerID.displayName)")
                #endif

                guard let secret = provider.decapsulate(ciphertext: ciphertext, privateKeyHandle: handle) else {
                    #if DEBUG
                    debugPrint("[KE] Decapsulation failed")
                    #endif
                    return
                }

                // ⚠️ Release SE private key — its only purpose is fulfilled.
                self.privateKeyHandle = nil
                let theirs = QuantumPayload(secret: secret, ciphertext: ciphertext)
                self.record(.ciphertext, by: self.peerRole, data)
                self.stepProgress()

                #if DEBUG
                debugPrint("[KE] Decapsulation succeeded")
                #endif

                if self.isInitiator {
                    self.exchangeStatus = .complete(ours: ours, theirs: theirs)
                    self.assembleHybridResult(ours: ours, theirs: theirs)
                } else {
                    // Received initiator's ciphertext → send ours.
                    self.exchangeStatus = .sendingMyQuantum(ours: ours, theirs: theirs)
                    let generation = self.generation
                    Task { @MainActor [weak self] in
                        try? await Task.sleep(for: delay)
                        guard let self, self.generation == generation,
                              case .sendingMyQuantum(let ours, let theirs?) = self.exchangeStatus else { return }
                        guard self.sendCiphertext(ours.ciphertext, to: peerID) else { return }
                        self.exchangeStatus = .complete(ours: ours, theirs: theirs)
                        self.assembleHybridResult(ours: ours, theirs: theirs)
                    }
                }
                return
            }
        } catch {
            #if DEBUG
            debugPrint("[KE] Exchange decode failed: \(error)")
            #endif
        }
    }

    private func handleNearbyObjectsUpdate(_ nearbyObjects: [NINearbyObject]) {
        // Any NI update proves the subsystem is alive — reset watchdog before distance filter. Not once the exchange is
        // under way: its steps have a deadline of their own, which ranging does not move (Bug 198).
        if !self.protocolInProgress { self.scheduleWatchdog() }

        for object in nearbyObjects {
            if let d = object.distance { self.distance = d }
            if let dir = object.direction { self.direction = dir }

            guard let distance = object.distance, distance.isLessThanOrEqualTo(0.25) else { continue }

            if self.phase == .found || self.phase == .searching { self.phase = .connected }

            #if DEBUG
            debugPrint("[KE] Object in range")
            #endif

            let token = object.discoveryToken
            guard let peer = self.receivedDiscoveryTokens[token] else { continue }

            #if DEBUG
            debugPrint("[KE] Discovery token matches peer: \(peer.displayName)")
            #endif

            // Protocol starts exactly once.
            guard self.exchangeStatus == nil else { continue }

            self.startProtocol(with: peer)
        }
    }

    /// Proximity is confirmed and the peer is the one we are pinned to, and has committed to its nonce: the exchange's steps
    /// begin. Not `private`, so tests can start an exchange without NearbyInteraction.
    func startProtocol(with peer: MCPeerID) {
        guard self.exchangeStatus == nil, self.peerCommitment != nil, peer == self.connectedPeerID else { return }
        self.protocolInProgress = true
        self.armStepDeadline()
        let delay = self.stepDelay

        if self.isInitiator {
            self.exchangeStatus = .sendingMyIdentity(ours: nil)
            #if DEBUG
            debugPrint("[KE] Initiator — sending identity in 3s")
            #endif
            let generation = self.generation
            Task { @MainActor [weak self] in
                try? await Task.sleep(for: delay)
                guard let self, self.generation == generation, case .sendingMyIdentity = self.exchangeStatus else { return }
                guard self.sendIdentity(to: peer) else { return }
                self.exchangeStatus = .waitingForPeerIdentity
            }
        } else {
            self.exchangeStatus = .waitingForPeerIdentity
            #if DEBUG
            debugPrint("[KE] Responder — waiting for initiator's identity")
            #endif
        }

        // Replay identity that arrived before NI confirmed proximity.
        if let buffered = self.bufferedIdentityMessage {
            self.bufferedIdentityMessage = nil
            self.handleReceivedData(buffered.data, from: buffered.peerID)
        }
    }
}

// MARK: - MCSessionDelegate
// ⚠️ All delegate callbacks dispatch to the main queue before mutating state.

extension ExchangeManager: MCSessionDelegate {
    func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        let generation = self.generation
        DispatchQueue.main.async { [weak self] in
            // Dropped if the exchange ended while this waited, or if it is another session's: a stale connect must not
            // pin a new exchange to the old peer (Bug 200).
            guard let self, self.generation == generation, self.multipeerSession === session else { return }
            #if DEBUG
            debugPrint("[KE] Session state changed: \(state.rawValue) for \(peerID.displayName)")
            #endif
            self.handleSessionStateChange(peerID: peerID, state: state)
        }
    }

    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        let generation = self.generation
        DispatchQueue.main.async { [weak self] in
            guard let self, self.generation == generation, self.multipeerSession === session else { return }
            #if DEBUG
            debugPrint("[KE] Received data from \(peerID.displayName)")
            #endif
            self.handleReceivedData(data, from: peerID)
        }
    }

    func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) { }
    func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, with progress: Progress) { }
    func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, at localURL: URL?, withError error: (any Error)?) { }
}

// MARK: - MCNearbyServiceBrowserDelegate

extension ExchangeManager: MCNearbyServiceBrowserDelegate {
    func browser(_ browser: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID, withDiscoveryInfo info: [String: String]?) {
        #if DEBUG
        debugPrint("[KE] Browser found peer: \(peerID.displayName)")
        #endif
        guard let session = self.multipeerSession else { return }
        guard peerID.displayName != session.myPeerID.displayName,
              !session.connectedPeers.contains(peerID) else { return }
        browser.invitePeer(peerID, to: session, withContext: nil, timeout: 30)
    }

    func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) { }
}

// MARK: - MCNearbyServiceAdvertiserDelegate

extension ExchangeManager: MCNearbyServiceAdvertiserDelegate {
    func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer peerID: MCPeerID, withContext context: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        #if DEBUG
        debugPrint("[KE] Advertiser received invitation from: \(peerID.displayName)")
        #endif
        invitationHandler(true, self.multipeerSession)
    }
}

// MARK: - NISessionDelegate
// ⚠️ NI delegate callbacks dispatch to the main queue before mutating state.

extension ExchangeManager: NISessionDelegate {
    func session(_ session: NISession, didUpdate nearbyObjects: [NINearbyObject]) {
        let generation = self.generation
        DispatchQueue.main.async { [weak self] in
            // An update that was queued when the exchange ended would arm the watchdog on a manager at rest (Bug 200).
            guard let self, self.generation == generation else { return }
            #if DEBUG
            let distances = nearbyObjects.map { $0.distance.map { String(format: "%.2f", $0) } ?? "nil" }
            debugPrint("[KE] NI didUpdate: distances: \(distances)")
            #endif
            self.handleNearbyObjectsUpdate(nearbyObjects)
        }
    }

    func session(_ session: NISession, didInvalidateWith error: Error) {
        #if DEBUG
        debugPrint("[KE] NI didInvalidateWith error: \(error)")
        if let niError = error as? NIError {
            debugPrint("[KE] NIError code: \(niError.code.rawValue)")
        }
        #endif
    }

    func session(_ session: NISession, didRemove nearbyObjects: [NINearbyObject], reason: NINearbyObject.RemovalReason) {
        #if DEBUG
        debugPrint("[KE] NI didRemove \(nearbyObjects.count) objects, reason: \(reason.rawValue)")
        #endif
    }

    func sessionWasSuspended(_ session: NISession) {
        #if DEBUG
        debugPrint("[KE] NI sessionWasSuspended")
        #endif
    }

    func sessionSuspensionEnded(_ session: NISession) {
        #if DEBUG
        debugPrint("[KE] NI sessionSuspensionEnded — re-running configuration")
        #endif
        if let config = self.lastNIConfiguration {
            session.run(config)
        }
    }

    func sessionDidStartRunning(_ session: NISession) {
        #if DEBUG
        debugPrint("[KE] NISession started running")
        #endif
    }
}
