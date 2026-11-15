//
//  FuzzEngine.swift
//  OccultaTests
//
//  The deterministic mutation fuzzer behind `DecoderFuzzTests` (hardening step 12, register D6).
//  No dependency, no Swift Testing: it is plain Foundation, so the same file also builds into a
//  standalone command-line harness, where a trap kills one process and not a test host.
//
//  What a run is
//  -------------
//  A target is a decoder, reduced to "bytes in, any outcome out". A case is one input: a seed from the
//  target's corpus (the recorded vectors, plus encodings built with the real encoders) put through one to
//  four mutations. A case passes if the decoder returns, throws or answers nil. It fails if it
//  - violates a property the target checks (an accepted input must re-encode consistently),
//  - runs longer than `caseTimeLimit` (a hang),
//  - grows the process by more than `memoryGrowthLimit` (1 GiB) (a runaway allocation), or
//  - traps, which no code here can catch: the process dies, and the trace file names the case.
//
//  Every case is a pure function of (target, seed, iteration). `FuzzRandom(seed:iteration:)` is derived from
//  those two numbers alone, so any single case replays without running the ones before it.
//

import Foundation

// MARK: - Random

/// SplitMix64. Small, fast, and identical on every platform, which `SystemRandomNumberGenerator` is not.
nonisolated struct FuzzRandom: RandomNumberGenerator {
    private var state: UInt64

    init(state: UInt64) { self.state = state }

    /// The generator of one case. Two numbers in, one stream out; neighbouring iterations share nothing.
    init(seed: UInt64, iteration: Int) {
        var mixer = FuzzRandom(state: seed ^ (UInt64(truncatingIfNeeded: iteration) &* 0xD6E8_FEB8_6659_FD93))
        _ = mixer.next()
        self.state = mixer.next()
    }

    mutating func next() -> UInt64 {
        self.state &+= 0x9E37_79B9_7F4A_7C15
        var z = self.state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    mutating func below(_ bound: Int) -> Int {
        bound <= 1 ? 0 : Int(self.next() % UInt64(bound))
    }

    mutating func chance(_ oneIn: Int) -> Bool { self.below(oneIn) == 0 }

    mutating func pick<T>(_ items: [T]) -> T { items[self.below(items.count)] }
}

// MARK: - Corpus

/// A big-endian integer the format puts in the bytes: where it starts and how wide it is.
nonisolated struct FuzzLengthField: Sendable {
    let offset: Int
    let width: Int
}

/// One valid encoding to mutate, and where its length and count fields sit.
nonisolated struct FuzzSeedInput: Sendable {
    let name: String
    let bytes: Data
    let lengthFields: [FuzzLengthField]
    /// JSON or other text, which also gets token-level mutations: a number swapped for an extreme, a value
    /// for another type, brackets nested deep.
    let isText: Bool
    /// Whether the decoder must accept the seed as it is. A suite check, so a seed that stops decoding
    /// (and a fuzzer that mutates nothing real) shows up instead of passing quietly.
    let isValid: Bool

    init(_ name: String, _ bytes: Data, lengthFields: [FuzzLengthField] = [], isText: Bool = false, isValid: Bool = true) {
        self.name = name
        self.bytes = bytes
        self.lengthFields = lengthFields
        self.isText = isText
        self.isValid = isValid
    }
}

nonisolated struct FuzzViolation: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// A target's way of saying "refused", where it also has a second thing to check afterwards. Any error is a refusal;
/// this one just says so on purpose.
nonisolated struct FuzzRejection: Error {}

/// A decoder under test.
nonisolated protocol FuzzTarget: Sendable {
    var name: String { get }
    var corpus: [FuzzSeedInput] { get }
    /// Whether the decoder is also handed a `Data` slice that doesn't start at index 0. `Data` is
    /// allowed to be one, and a decoder that indexes with literals reads or traps out of range.
    var acceptsSlices: Bool { get }
    /// Decode `input`. Return, or throw anything: all are fine. Throw `FuzzViolation` for a property the
    /// target checks and the decoder broke.
    func run(_ input: Data) throws
}

extension FuzzTarget {
    var acceptsSlices: Bool { true }
}

/// A decoder that lives in the app and is isolated to the main actor, as everything in the app module is by default.
/// It can't be called from a worker thread, so `Fuzzer.runOnMainActor` runs it on the caller's.
@MainActor
protocol MainActorFuzzTarget {
    var name: String { get }
    var corpus: [FuzzSeedInput] { get }
    var acceptsSlices: Bool { get }
    func run(_ input: Data) throws
}

extension MainActorFuzzTarget {
    var acceptsSlices: Bool { true }
}

// MARK: - Mutation

nonisolated enum FuzzMutator {

    /// No input grows past this, so a case costs microseconds however the mutations stack.
    static let maxLength = 1 << 20

    private static let boundaryBytes: [UInt8] = [0x00, 0x7F, 0x80, 0xFF]

    /// `seed` put through one to four mutations. Returns the bytes and the names of what was done, for the report.
    static func mutate(_ seed: FuzzSeedInput, corpus: [FuzzSeedInput], rng: inout FuzzRandom) -> (bytes: Data, operations: [String]) {
        var bytes = [UInt8](seed.bytes)
        var operations: [String] = []

        for _ in 0..<(1 + rng.below(4)) {
            let operation = Operation.allCases[rng.below(Operation.allCases.count)]
            operation.apply(to: &bytes, seed: seed, corpus: corpus, rng: &rng)
            operations.append(operation.rawValue)
            if bytes.count > Self.maxLength { bytes.removeLast(bytes.count - Self.maxLength) }
        }
        return (Data(bytes), operations)
    }

    enum Operation: String, CaseIterable {
        case bitFlip
        case boundaryOverwrite
        case randomOverwrite
        case truncate
        case extend
        case duplicateRange
        case deleteRange
        case splice
        case lengthField
        case lengthFieldAfterTruncate
        case textToken
        case deepNesting
        case bareNesting

        func apply(to bytes: inout [UInt8], seed: FuzzSeedInput, corpus: [FuzzSeedInput], rng: inout FuzzRandom) {
            switch self {
            case .bitFlip:
                guard !bytes.isEmpty else { return }
                for _ in 0..<(1 + rng.below(3)) {
                    bytes[rng.below(bytes.count)] ^= UInt8(1 << rng.below(8))
                }

            case .boundaryOverwrite:
                guard !bytes.isEmpty else { return }
                let value = rng.pick(FuzzMutator.boundaryBytes)
                let width = rng.pick([1, 1, 2, 4, 8])
                let start = rng.below(bytes.count)
                for index in start..<min(bytes.count, start + width) { bytes[index] = value }

            case .randomOverwrite:
                guard !bytes.isEmpty else { return }
                let start = rng.below(bytes.count)
                for index in start..<min(bytes.count, start + 1 + rng.below(32)) { bytes[index] = UInt8(truncatingIfNeeded: rng.next()) }

            case .truncate:
                guard !bytes.isEmpty else { return }
                // Often one byte short of an edge, since an off-by-one is what a truncation finds.
                let keep = rng.chance(3) ? max(0, bytes.count - 1 - rng.below(8)) : rng.below(bytes.count)
                bytes.removeLast(bytes.count - keep)

            case .extend:
                let count = rng.pick([1, 3, 8, 17, 64, 4096])
                switch rng.below(3) {
                case 0:  bytes.append(contentsOf: (0..<count).map { _ in UInt8(truncatingIfNeeded: rng.next()) })
                case 1:  bytes.append(contentsOf: [UInt8](repeating: 0xFF, count: count))
                default: bytes.append(contentsOf: [UInt8](repeating: 0x00, count: count))
                }

            case .duplicateRange:
                guard !bytes.isEmpty else { return }
                let start = rng.below(bytes.count)
                let end = min(bytes.count, start + 1 + rng.below(256))
                bytes.insert(contentsOf: bytes[start..<end], at: rng.below(bytes.count + 1))

            case .deleteRange:
                guard !bytes.isEmpty else { return }
                let start = rng.below(bytes.count)
                bytes.removeSubrange(start..<min(bytes.count, start + 1 + rng.below(256)))

            case .splice:
                // This seed's start and another seed's end, cut at independent offsets.
                let other = [UInt8](rng.pick(corpus).bytes)
                bytes = Array(bytes.prefix(rng.below(bytes.count + 1))) + Array(other.suffix(rng.below(other.count + 1)))

            case .lengthField:
                FuzzMutator.setLengthField(&bytes, seed: seed, rng: &rng)

            case .lengthFieldAfterTruncate:
                // The value a length field takes when it claims exactly one byte more than the file holds.
                FuzzMutator.setLengthField(&bytes, seed: seed, rng: &rng, claim: .justPastEnd)
                if !bytes.isEmpty { bytes.removeLast(rng.below(min(bytes.count, 4) + 1)) }

            case .textToken:
                guard seed.isText else { Operation.bitFlip.apply(to: &bytes, seed: seed, corpus: corpus, rng: &rng); return }
                FuzzMutator.swapToken(&bytes, rng: &rng)

            case .deepNesting:
                guard seed.isText, !bytes.isEmpty else { Operation.truncate.apply(to: &bytes, seed: seed, corpus: corpus, rng: &rng); return }
                let opening = rng.pick([Array("[".utf8), Array("{\"a\":".utf8)])
                bytes.insert(contentsOf: Array((0..<FuzzMutator.nestingDepth(&rng)).map { _ in opening }.joined()), at: rng.below(bytes.count + 1))

            case .bareNesting:
                // Nothing but opening brackets, as many as the depth limits of the JSON parsers make interesting. Foundation's
                // traps on exactly 513 of them and nothing else (`bugs.md` Bug 189), which no other shape of input finds.
                guard seed.isText else { Operation.bitFlip.apply(to: &bytes, seed: seed, corpus: corpus, rng: &rng); return }
                bytes = [UInt8](repeating: rng.pick([UInt8(ascii: "["), UInt8(ascii: "{")]), count: FuzzMutator.nestingDepth(&rng))
            }
        }
    }

    /// A nesting depth worth trying: either side of the limits that matter. 64 is `BoundedJSON`'s, 512 Foundation's.
    static func nestingDepth(_ rng: inout FuzzRandom) -> Int {
        rng.pick([1, 63, 64, 65, 511, 512, 513, 514, 600, 20_000])
    }

    /// Replaces a run of number characters, or a quoted value, with something a decoder may not expect.
    private static func swapToken(_ bytes: inout [UInt8], rng: inout FuzzRandom) {
        let numeric: Set<UInt8> = Set("0123456789.eE+-".utf8)
        let replacements: [String] = [
            "-1", "0", "1", "-0", "255", "256", "65536", "2147483648", "4294967296", "9223372036854775807", "9223372036854775808",
            "-9223372036854775808", "18446744073709551615", "18446744073709551616", "1e30", "-1e12", "1e400", "-1e400", "0.5",
            "null", "true", "\"\"", "[]", "{}", "\"\\ud800\"", "\"" + String(repeating: "A", count: 4_096) + "\"",
        ]
        var runs: [Range<Int>] = []
        var index = 0
        while index < bytes.count {
            if numeric.contains(bytes[index]) {
                var end = index
                while end < bytes.count, numeric.contains(bytes[end]) { end += 1 }
                runs.append(index..<end)
                index = end
            } else {
                index += 1
            }
        }
        // Quoted values too: the span between two quotes.
        var quote: Int?
        for position in bytes.indices where bytes[position] == UInt8(ascii: "\"") {
            if let open = quote { runs.append(open..<(position + 1)); quote = nil } else { quote = position }
        }
        guard !runs.isEmpty else { return }
        bytes.replaceSubrange(rng.pick(runs), with: Array(rng.pick(replacements).utf8))
    }

    private enum Claim { case any, justPastEnd }

    /// Writes 0, the maximum, the high bit, or a value near the bytes remaining into one of the seed's
    /// length fields. Without length fields it falls back to a boundary overwrite.
    private static func setLengthField(_ bytes: inout [UInt8], seed: FuzzSeedInput, rng: inout FuzzRandom, claim: Claim = .any) {
        guard let field = seed.lengthFields.isEmpty ? nil : seed.lengthFields[rng.below(seed.lengthFields.count)],
              field.offset + field.width <= bytes.count
        else {
            if !bytes.isEmpty { bytes[rng.below(bytes.count)] = rng.pick(Self.boundaryBytes) }
            return
        }

        let remaining = UInt64(bytes.count - (field.offset + field.width))
        let top: UInt64 = field.width >= 8 ? .max : (1 << UInt64(field.width * 8)) - 1
        let high: UInt64 = field.width >= 8 ? 1 << 63 : 1 << UInt64(field.width * 8 - 1)

        let value: UInt64
        switch claim {
        case .justPastEnd:
            value = min(top, remaining &+ 1)
        case .any:
            value = rng.pick([0, 1, top, top &- 1, high, high &- 1, remaining, remaining &+ 1, remaining &- 1, remaining &+ 1000])
        }

        let clamped = min(value, top)
        for index in 0..<field.width {
            bytes[field.offset + index] = UInt8(truncatingIfNeeded: clamped >> UInt64(8 * (field.width - 1 - index)))
        }
    }
}

// MARK: - Configuration

/// What a run is allowed to cost, and the environment variables that change it.
///
/// Under `xcodebuild` the variables are passed as `TEST_RUNNER_<NAME>`; the test process sees `<NAME>`.
nonisolated struct FuzzConfiguration: Sendable {
    /// The seeds the committed suite runs. Fixed: a failure in CI names one of these.
    static let committedSeeds: [UInt64] = [1, 2, 3, 4]

    var seeds: [UInt64] = Self.committedSeeds
    /// Cases per target and seed. The committed default keeps the whole suite to seconds.
    var iterations = 400
    /// When set, only this iteration of each seed runs: the replay of a reported failure.
    var onlyIteration: Int?
    /// When set, only the target with this name runs.
    var onlyTarget: String?
    /// Where to write the case about to run, so a trap (which no handler sees) can still be traced to its case.
    var tracePath: String?
    var caseTimeLimit: TimeInterval = 5
    var memoryGrowthLimit: UInt64 = 1 << 30

    static var fromEnvironment: FuzzConfiguration {
        let environment = ProcessInfo.processInfo.environment
        var configuration = FuzzConfiguration()
        if let seed = environment["OCCULTA_FUZZ_SEED"].flatMap({ UInt64($0) }) { configuration.seeds = [seed] }
        if let count = environment["OCCULTA_FUZZ_ITERATIONS"].flatMap({ Int($0) }), count > 0 { configuration.iterations = count }
        configuration.onlyIteration = environment["OCCULTA_FUZZ_ITERATION"].flatMap { Int($0) }
        configuration.onlyTarget = environment["OCCULTA_FUZZ_TARGET"]
        configuration.tracePath = environment["OCCULTA_FUZZ_TRACE"]
        if let limit = environment["OCCULTA_FUZZ_CASE_SECONDS"].flatMap({ TimeInterval($0) }), limit > 0 { configuration.caseTimeLimit = limit }
        return configuration
    }
}

// MARK: - Result

nonisolated struct FuzzFailure: CustomStringConvertible, Sendable {
    enum Kind: String, Sendable { case violation, hang, memory }

    let target: String
    let seed: UInt64
    let iteration: Int
    let kind: Kind
    let detail: String
    let seedName: String
    let operations: [String]
    let inputHex: String

    var description: String {
        """
        \(self.kind.rawValue) in \(self.target): \(self.detail)
          replay: TEST_RUNNER_OCCULTA_FUZZ_TARGET='\(self.target)' TEST_RUNNER_OCCULTA_FUZZ_SEED=\(self.seed) \
        TEST_RUNNER_OCCULTA_FUZZ_ITERATION=\(self.iteration)
          from \(self.seedName), mutated by \(self.operations.joined(separator: ", "))
          input: \(self.inputHex)
        """
    }
}

nonisolated struct FuzzReport: Sendable {
    var cases = 0
    var accepted = 0
    var failures: [FuzzFailure] = []
    var seconds: TimeInterval = 0
}

// MARK: - Runner

nonisolated enum Fuzzer {

    /// Runs `iterations` cases of `target` under `seed` on a worker thread, and watches it from this one.
    ///
    /// The worker is a thread of its own for one reason: a decoder that never returns can't be interrupted
    /// from inside, but it can be given up on from outside. The stack is 1 MiB, the iOS main thread's, so a
    /// decoder that recurses is tried at the depth it has in the app.
    static func run(_ target: some FuzzTarget, seed: UInt64, configuration: FuzzConfiguration) -> FuzzReport {
        let progress = Progress(memoryLimit: configuration.memoryGrowthLimit)
        let finished = DispatchSemaphore(value: 0)
        let started = DispatchTime.now().uptimeNanoseconds

        let iterations = configuration.onlyIteration.map { $0..<($0 + 1) } ?? 0..<configuration.iterations
        let trace = configuration.tracePath.flatMap { TraceFile(path: $0) }

        let worker = Thread {
            Self.work(target, seed: seed, iterations: iterations, progress: progress, trace: trace)
            finished.signal()
        }
        worker.stackSize = 1 << 20
        worker.qualityOfService = .userInitiated
        worker.start()

        var report = FuzzReport()
        while finished.wait(timeout: .now() + .milliseconds(2)) == .timedOut {
            guard let running = progress.inFlight() else { continue }

            progress.noteGrowth(since: running.baseline)
            let elapsed = Double(DispatchTime.now().uptimeNanoseconds - running.startedAt) / 1e9
            guard elapsed > configuration.caseTimeLimit else { continue }

            // Given up on, not stopped: a hung worker spins until the process ends. The suite goes on without it.
            progress.abandon()
            report.failures.append(running.failure(
                target: target.name, seed: seed, kind: .hang, detail: "no result after \(String(format: "%.1f", elapsed)) s"
            ))
            break
        }

        let outcome = progress.outcome()
        report.cases = outcome.cases
        report.accepted = outcome.accepted
        report.failures.append(contentsOf: outcome.failures)
        report.seconds = Double(DispatchTime.now().uptimeNanoseconds - started) / 1e9
        return report
    }

    private static func work(_ target: some FuzzTarget, seed: UInt64, iterations: Range<Int>, progress: Progress, trace: TraceFile?) {
        Self.cases(
            name: target.name, corpus: target.corpus, acceptsSlices: target.acceptsSlices,
            seed: seed, iterations: iterations, progress: progress, trace: trace, execute: { try target.run($0) }
        )
    }

    /// The loop both runners share: build the case, announce it, run it, record what came of it.
    private static func cases(
        name: String, corpus: [FuzzSeedInput], acceptsSlices: Bool, seed: UInt64, iterations: Range<Int>,
        progress: Progress, trace: TraceFile?, execute: (Data) throws -> Void
    ) {
        guard !corpus.isEmpty else { return }

        for iteration in iterations {
            if progress.isAbandoned { return }

            let (chosen, operations, input) = Self.makeCase(acceptsSlices: acceptsSlices, corpus: corpus, seed: seed, iteration: iteration)
            trace?.write("target=\(name) seed=\(seed) iteration=\(iteration) from=\(chosen.name) ops=\(operations.joined(separator: ","))")
            progress.begin(
                iteration: iteration, target: name, seedName: chosen.name, operations: operations,
                input: input, baseline: FuzzMemory.footprint()
            )
            var violation: FuzzViolation?
            var accepted = true
            do {
                try execute(input)
            } catch let error as FuzzViolation {
                violation = error
            } catch {
                accepted = false
            }
            progress.end(violation: violation.map { ($0.description, seed) }, accepted: accepted, target: name, seed: seed)
        }
    }

    // MARK: Main-actor targets

    /// Runs a main-actor target on the main actor, which is the only place it may run.
    ///
    /// The main actor is given back between cases. A run that held it for its whole length would hold up every other
    /// test that needs it, and in a full run that was enough to change how the others interleave: two of them, which
    /// share the app's `Drafts/` directory and the share staging key, began to fail.
    ///
    /// A watchdog thread stands in for the one `run` has. It can't give up on the main thread, so a hang ends the
    /// process: it writes the case, with its replay line, to stderr and aborts. That is a failure a log can name, which
    /// a test host that hangs until CI kills it is not. A memory jump is only noted, and reported when the case ends.
    @MainActor
    static func runOnMainActor(_ target: some MainActorFuzzTarget, seed: UInt64, configuration: FuzzConfiguration) async -> FuzzReport {
        let progress = Progress(memoryLimit: configuration.memoryGrowthLimit)
        let started = DispatchTime.now().uptimeNanoseconds
        let iterations = configuration.onlyIteration.map { $0..<($0 + 1) } ?? 0..<configuration.iterations
        let trace = configuration.tracePath.flatMap { TraceFile(path: $0) }
        let targetName = target.name

        let watchdog = Thread {
            while !progress.isAbandoned {
                Thread.sleep(forTimeInterval: 0.01)
                guard let running = progress.inFlight() else { continue }
                progress.noteGrowth(since: running.baseline)
                let elapsed = Double(DispatchTime.now().uptimeNanoseconds - running.startedAt) / 1e9
                guard elapsed > configuration.caseTimeLimit else { continue }
                let failure = running.failure(
                    target: targetName, seed: seed, kind: .hang, detail: "no result after \(String(format: "%.1f", elapsed)) s"
                )
                FileHandle.standardError.write(Data("\n\(failure)\n".utf8))
                abort()
            }
        }
        watchdog.stackSize = 1 << 18
        watchdog.start()
        defer { progress.abandon() }

        // The same loop as `cases`, with the main actor given back after every case.
        let corpus = target.corpus
        if !corpus.isEmpty {
            for iteration in iterations {
                let (chosen, operations, input) = Self.makeCase(acceptsSlices: target.acceptsSlices, corpus: corpus, seed: seed, iteration: iteration)
                trace?.write("target=\(targetName) seed=\(seed) iteration=\(iteration) from=\(chosen.name) ops=\(operations.joined(separator: ","))")
                progress.begin(
                    iteration: iteration, target: targetName, seedName: chosen.name, operations: operations,
                    input: input, baseline: FuzzMemory.footprint()
                )
                var violation: FuzzViolation?
                var accepted = true
                do {
                    try target.run(input)
                } catch let error as FuzzViolation {
                    violation = error
                } catch {
                    accepted = false
                }
                progress.end(violation: violation.map { ($0.description, seed) }, accepted: accepted, target: targetName, seed: seed)
                await Task.yield()
            }
        }

        let outcome = progress.outcome()
        return FuzzReport(
            cases: outcome.cases, accepted: outcome.accepted, failures: outcome.failures,
            seconds: Double(DispatchTime.now().uptimeNanoseconds - started) / 1e9
        )
    }

    /// `run`, on a thread of its own, so the caller can be `async` without a cooperative-pool thread sitting in the
    /// watcher's loop for seconds.
    static func runAsync(_ target: some FuzzTarget, seed: UInt64, configuration: FuzzConfiguration) async -> FuzzReport {
        await withCheckedContinuation { continuation in
            let thread = Thread { continuation.resume(returning: Self.run(target, seed: seed, configuration: configuration)) }
            thread.stackSize = 1 << 18
            thread.start()
        }
    }

    /// The input of one case: a pure function of the target, the seed and the iteration, which is what makes a
    /// reported failure replayable on its own.
    static func makeCase(_ target: some FuzzTarget, corpus: [FuzzSeedInput], seed: UInt64, iteration: Int) -> (chosen: FuzzSeedInput, operations: [String], input: Data) {
        Self.makeCase(acceptsSlices: target.acceptsSlices, corpus: corpus, seed: seed, iteration: iteration)
    }

    static func makeCase(acceptsSlices: Bool, corpus: [FuzzSeedInput], seed: UInt64, iteration: Int) -> (chosen: FuzzSeedInput, operations: [String], input: Data) {
        var rng = FuzzRandom(seed: seed, iteration: iteration)
        let chosen = corpus[rng.below(corpus.count)]
        // One case in eight is the seed untouched: the decoder must accept what the encoder wrote.
        let (mutated, operations) = rng.chance(8)
            ? (chosen.bytes, ["unmodified"])
            : FuzzMutator.mutate(chosen, corpus: corpus, rng: &rng)
        let input = acceptsSlices && rng.chance(4) ? Self.slice(of: mutated, rng: &rng) : mutated
        return (chosen, operations, input)
    }

    /// `bytes` as a slice of a longer buffer, so its `startIndex` is not 0.
    private static func slice(of bytes: Data, rng: inout FuzzRandom) -> Data {
        let padding = 1 + rng.below(16)
        let wide = Data(repeating: UInt8(truncatingIfNeeded: rng.next()), count: padding) + bytes
        return wide[padding...]
    }

    // MARK: State shared with the watcher

    private final class Progress: @unchecked Sendable {
        struct InFlight {
            let iteration: Int
            let startedAt: UInt64
            let baseline: UInt64
            let seedName: String
            let operations: [String]
            let input: Data

            func failure(target: String, seed: UInt64, kind: FuzzFailure.Kind, detail: String) -> FuzzFailure {
                FuzzFailure(
                    target: target, seed: seed, iteration: self.iteration, kind: kind, detail: detail,
                    seedName: self.seedName, operations: self.operations, inputHex: Hex.encode(self.input)
                )
            }
        }

        private let lock = NSLock()
        private let memoryLimit: UInt64
        private var peakGrowth: UInt64 = 0
        private var running: InFlight?
        private var abandoned = false
        private var cases = 0
        private var accepted = 0
        private var failures: [FuzzFailure] = []

        init(memoryLimit: UInt64) { self.memoryLimit = memoryLimit }

        var isAbandoned: Bool { self.lock.withLock { self.abandoned } }

        /// The watchdog's sample: how far the process has grown since the case began. Only the peak is kept, and
        /// `end` turns it into a failure, so a jump caused by something else in the process (another test, in a full
        /// run) fails this case and not the run.
        func noteGrowth(since baseline: UInt64) {
            let footprint = FuzzMemory.footprint()
            let grown = footprint > baseline ? footprint - baseline : 0
            self.lock.withLock { self.peakGrowth = max(self.peakGrowth, grown) }
        }

        func abandon() { self.lock.withLock { self.abandoned = true } }

        func inFlight() -> InFlight? { self.lock.withLock { self.running } }

        func begin(iteration: Int, target: String, seedName: String, operations: [String], input: Data, baseline: UInt64) {
            self.lock.withLock {
                self.running = InFlight(
                    iteration: iteration, startedAt: DispatchTime.now().uptimeNanoseconds, baseline: baseline,
                    seedName: seedName, operations: operations, input: input
                )
                self.peakGrowth = 0
            }
        }

        func end(violation: (String, UInt64)?, accepted: Bool, target: String, seed: UInt64) {
            self.lock.withLock {
                if let running = self.running, self.failures.count < 5 {
                    if let violation {
                        self.failures.append(running.failure(target: target, seed: violation.1, kind: .violation, detail: violation.0))
                    } else if self.peakGrowth > self.memoryLimit {
                        self.failures.append(running.failure(
                            target: target, seed: seed, kind: .memory, detail: "process grew by \(self.peakGrowth >> 20) MiB in one case"
                        ))
                    }
                }
                self.cases += 1
                if accepted { self.accepted += 1 }
                self.running = nil
            }
        }

        func outcome() -> (cases: Int, accepted: Int, failures: [FuzzFailure]) {
            self.lock.withLock { (self.cases, self.accepted, self.failures) }
        }
    }
}

// MARK: - Support

nonisolated enum Hex {
    static func encode(_ data: Data, limit: Int = 2_048) -> String {
        let shown = data.prefix(limit).map { String(format: "%02x", $0) }.joined()
        return data.count > limit ? shown + "…(\(data.count) bytes)" : shown
    }

    static func decode(_ string: String) -> Data? {
        guard string.count.isMultiple(of: 2) else { return nil }
        var data = Data(capacity: string.count / 2)
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            guard let byte = UInt8(string[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return data
    }
}

/// The current case, overwritten in place before each one runs. After a trap the file holds the case that did it.
nonisolated final class TraceFile: @unchecked Sendable {
    private let descriptor: Int32

    init?(path: String) {
        let descriptor = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        guard descriptor >= 0 else { return nil }
        self.descriptor = descriptor
    }

    deinit { close(self.descriptor) }

    func write(_ line: String) {
        var bytes = Array((line + "\n").utf8)
        bytes.append(contentsOf: [UInt8](repeating: 0x20, count: max(0, 256 - bytes.count)))
        _ = pwrite(self.descriptor, bytes, bytes.count, 0)
    }
}

/// The process's physical footprint. Process-wide, so a case that runs beside another test's allocation sees
/// it too: the limit is a net for a blow-up of hundreds of megabytes, not a meter.
nonisolated enum FuzzMemory {
    static func footprint() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? UInt64(info.phys_footprint) : 0
    }
}
