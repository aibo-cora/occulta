//
//  DecoderFuzzTests.swift
//  OccultaTests
//
//  Hardening step 12 (`Docs/v2.0.0/HARDENING_STEPS.md`), register D6: nobody had ever fuzzed the decoders, and a
//  `.occ` file or an introduction card is the one input anyone can hand a user.
//
//  What runs
//  ---------
//  A fixed set of seeds (`FuzzConfiguration.committedSeeds`), each putting every target through the same number of
//  mutated inputs. The targets are in `FormatFuzzTargets` (`OccultaCore` and `OccultaFormats`, nonisolated, run on a
//  worker thread with a watchdog), `AppFuzzTargets` (the app's own decoders and codecs) and `StatefulFuzzTargets`
//  (the share extension's staging, the exchange's delegate, a streamed file through the receive path). The app's
//  targets run on the main actor, which is the only place they can.
//
//  A failing case names its seed and iteration. Replay it alone:
//
//      TEST_RUNNER_OCCULTA_FUZZ_TARGET='<name>' TEST_RUNNER_OCCULTA_FUZZ_SEED=<seed> \
//      TEST_RUNNER_OCCULTA_FUZZ_ITERATION=<n> xcodebuild … -only-testing:OccultaTests/DecoderFuzzTests test
//
//  A trap is not a failure the test can report: it ends the process. Run with `TEST_RUNNER_OCCULTA_FUZZ_TRACE=<file>`
//  and the file holds the case that was running when it died, in the same terms.
//
//  Local, longer runs: `TEST_RUNNER_OCCULTA_FUZZ_ITERATIONS=50000` (per target and seed), and
//  `TEST_RUNNER_OCCULTA_FUZZ_SEED=<n>` for a seed outside the committed set. The committed run is a few seconds.
//

import Testing
import Foundation
@testable import Occulta
@testable import OccultaFormats

@Suite("Decoder fuzzing (hardening step 12)", .serialized)
struct DecoderFuzzTests {

    private static let configuration = FuzzConfiguration.fromEnvironment

    private static func selected(_ name: String) -> Bool {
        self.configuration.onlyTarget.map { name.localizedCaseInsensitiveContains($0) } ?? true
    }

    private static func record(_ report: FuzzReport, for name: String, seed: UInt64) {
        // One line per target and seed, so CI shows where the time goes and the run shows it did the work.
        print("fuzz seed \(seed): \(name): \(report.cases) cases, \(report.accepted) accepted, \(String(format: "%.2f", report.seconds)) s")
        for failure in report.failures {
            Issue.record("seed \(seed): \(failure)")
        }
    }

    // MARK: - The committed fuzz

    @Test("OccultaCore and OccultaFormats decoders survive mutated input", arguments: DecoderFuzzTests.configuration.seeds)
    func formats(seed: UInt64) async {
        for target in FormatFuzzTargets.all where Self.selected(target.name) {
            let report = await Fuzzer.runAsync(target, seed: seed, configuration: Self.configuration)
            Self.record(report, for: target.name, seed: seed)
            #expect(report.cases > 0, "\(target.name) ran no cases")
        }
    }

    @Test("The app's decoders and sealed-field codecs survive mutated input", arguments: DecoderFuzzTests.configuration.seeds)
    @MainActor
    func app(seed: UInt64) async {
        for target in AppFuzzTargets.all where Self.selected(target.name) {
            let report = await Fuzzer.runOnMainActor(target, seed: seed, configuration: Self.configuration)
            Self.record(report, for: target.name, seed: seed)
            #expect(report.cases > 0, "\(target.name) ran no cases")
        }
    }

    /// The staged-file and session targets cost a few milliseconds a case, which the others' counts would turn into seconds.
    private static var stateful: FuzzConfiguration { self.configuration }

    @Test("A shared file, however malformed, is read or removed", arguments: DecoderFuzzTests.configuration.seeds)
    @MainActor
    func shareExtension(seed: UInt64) async {
        let targets: [any MainActorFuzzTarget] = [ShareSessionTarget(), ShareManifestSessionTarget()]
        for target in targets where Self.selected(target.name) {
            let report = await Fuzzer.runOnMainActor(target, seed: seed, configuration: Self.stateful)
            Self.record(report, for: target.name, seed: seed)
        }
    }

    @Test("A nearby phone's messages never move a pinned exchange", arguments: DecoderFuzzTests.configuration.seeds)
    @MainActor
    func exchange(seed: UInt64) async {
        let target = ExchangeSessionTarget()
        guard Self.selected(target.name) else { return }
        await target.pin()
        let report = await Fuzzer.runOnMainActor(target, seed: seed, configuration: Self.stateful)
        Self.record(report, for: target.name, seed: seed)
    }

    @Test("A streamed .occ is refused without a trace", .ambientTestKeyManager, arguments: DecoderFuzzTests.configuration.seeds)
    @MainActor
    func streamedReceive(seed: UInt64) async throws {
        let target = try StreamedReceiveTarget()
        guard Self.selected(target.name) else { return }
        // The pristine seeds open, or the run would only be testing refusals.
        for seed in target.corpus where seed.isValid {
            try target.run(seed.bytes)
        }
        let report = await Fuzzer.runOnMainActor(target, seed: seed, configuration: Self.stateful)
        Self.record(report, for: target.name, seed: seed)
    }

    // MARK: - The fuzzer itself

    /// Without these a green run could mean a fuzzer that mutates nothing, or one that cannot see a hang.
    @Suite("The fuzzer checks itself", .serialized)
    struct Calibration {

        /// A seed that stops decoding, or a decoder that stops accepting what its encoder writes, would otherwise
        /// pass quietly: every mutation of a refused seed is refused too.
        @Test("Every valid seed is accepted by its target")
        @MainActor
        func formatSeedsDecode() {
            for target in FormatFuzzTargets.all {
                for seed in target.corpus where seed.isValid {
                    #expect(throws: Never.self, "\(target.name) refused its own seed '\(seed.name)'") { try target.run(seed.bytes) }
                }
            }
        }

        @Test("Every valid seed of the app's targets is accepted")
        @MainActor
        func appSeedsDecode() {
            for target in AppFuzzTargets.all {
                for seed in target.corpus where seed.isValid {
                    #expect(throws: Never.self, "\(target.name) refused its own seed '\(seed.name)'") { try target.run(seed.bytes) }
                }
            }
        }

        /// The same check for the targets that touch a session, a store or a file: what they are given untouched, they accept.
        @Test("Every valid seed of the stateful targets is accepted", .ambientTestKeyManager)
        @MainActor
        func statefulSeedsRun() async throws {
            let exchange = ExchangeSessionTarget()
            await exchange.pin()
            let targets: [any MainActorFuzzTarget] = [ShareSessionTarget(), ShareManifestSessionTarget(), exchange, try StreamedReceiveTarget()]
            for target in targets {
                #expect(!target.corpus.filter(\.isValid).isEmpty, "\(target.name) has no valid seed")
                for seed in target.corpus where seed.isValid {
                    do { try target.run(seed.bytes) } catch { Issue.record("\(target.name) refused its own seed '\(seed.name)': \(error)") }
                }
            }
        }

        @Test("There is a recorded vector for every kind a target reads")
        func vectorsLoaded() {
            #expect(!FuzzVectors.all.isEmpty, "InteropVectors.json was not found in the test bundle")
            for kind in ["envelope", "groupEnvelope", "legacyBundle", "payload", "basket", "depth", "recipientPayload", "card", "streamManifest", "cardField", "challengeField"] {
                #expect(!FuzzVectors.entries(ofKind: kind).isEmpty, "no vector of kind \(kind)")
            }
        }

        @Test("A case is a pure function of target, seed and iteration, and a seed's streams differ")
        func deterministic() {
            let target = DepthCodecTarget()
            let corpus = target.corpus
            let first = Fuzzer.makeCase(target, corpus: corpus, seed: 7, iteration: 123)
            let again = Fuzzer.makeCase(target, corpus: corpus, seed: 7, iteration: 123)
            #expect(first.input == again.input && first.operations == again.operations)

            let inputs = Set((0..<200).map { Fuzzer.makeCase(target, corpus: corpus, seed: 7, iteration: $0).input })
            #expect(inputs.count > 20, "200 iterations gave \(inputs.count) distinct inputs")
            let other = Set((0..<200).map { Fuzzer.makeCase(target, corpus: corpus, seed: 8, iteration: $0).input })
            #expect(inputs != other)
        }

        @Test("Mutation reaches every operation, and the length fields are set to the boundaries")
        func mutationCoverage() {
            let seed = FuzzSeedInput("p", try! WireHandle.encode(payload: OccultaBundle.SealedPayload(message: Data("hello".utf8))), lengthFields: [FuzzLengthField(offset: 0, width: 4)], isText: true)
            var operations = Set<String>()
            var lengths = Set<UInt32>()
            for iteration in 0..<4_000 {
                var rng = FuzzRandom(seed: 1, iteration: iteration)
                let (bytes, applied) = FuzzMutator.mutate(seed, corpus: [seed], rng: &rng)
                operations.formUnion(applied)
                if bytes.count >= 4 { lengths.insert(bytes.prefix(4).reduce(0) { $0 << 8 | UInt32($1) }) }
            }
            #expect(operations == Set(FuzzMutator.Operation.allCases.map(\.rawValue)), "operations seen: \(operations.sorted())")
            for boundary: UInt32 in [0, 1, .max, 1 << 31, (1 << 31) - 1] { #expect(lengths.contains(boundary), "length field never set to \(boundary)") }
        }

        private struct Violating: FuzzTarget {
            let name = "violating"
            var corpus: [FuzzSeedInput] { [FuzzSeedInput("s", Data([1, 2, 3, 4]))] }
            func run(_ input: Data) throws { if input.count == 2 { throw FuzzViolation("a two-byte input") } }
        }

        private struct Sleeping: FuzzTarget {
            let name = "sleeping"
            var corpus: [FuzzSeedInput] { [FuzzSeedInput("s", Data([1]))] }
            func run(_ input: Data) throws { Thread.sleep(forTimeInterval: 1.5) }
        }

        private struct Allocating: FuzzTarget {
            let name = "allocating"
            var corpus: [FuzzSeedInput] { [FuzzSeedInput("s", Data([1]))] }
            func run(_ input: Data) throws {
                var big = [UInt8](repeating: 1, count: 400 << 20)
                big[big.count - 1] = 2
                Thread.sleep(forTimeInterval: 0.5)
                if big[1] == 3 { throw FuzzViolation("never") }
            }
        }

        @Test("A property violation is reported with its seed and iteration")
        func reportsViolations() {
            var configuration = FuzzConfiguration()
            configuration.iterations = 400
            let report = Fuzzer.run(Violating(), seed: 3, configuration: configuration)
            #expect(!report.failures.isEmpty)
            #expect(report.failures.allSatisfy { $0.kind == .violation && $0.seed == 3 })
            // Replayable alone: the iteration it names produces the input that failed.
            if let failure = report.failures.first {
                var replay = configuration
                replay.onlyIteration = failure.iteration
                #expect(Fuzzer.run(Violating(), seed: 3, configuration: replay).failures.count == 1)
            }
        }

        @Test("A case that does not return is reported as a hang, not waited for")
        func reportsHangs() {
            var configuration = FuzzConfiguration()
            configuration.iterations = 5
            configuration.caseTimeLimit = 0.2
            let start = Date()
            let report = Fuzzer.run(Sleeping(), seed: 1, configuration: configuration)
            #expect(report.failures.first?.kind == .hang)
            #expect(report.failures.first?.iteration == 0)
            #expect(Date().timeIntervalSince(start) < 1.2, "the run waited for the hung case")
        }

        @Test("A case that grows the process past the limit is reported")
        func reportsMemory() {
            var configuration = FuzzConfiguration()
            configuration.iterations = 3
            configuration.memoryGrowthLimit = 100 << 20
            let report = Fuzzer.run(Allocating(), seed: 1, configuration: configuration)
            #expect(report.failures.first?.kind == .memory)
        }
    }
}
