//
//  OccultaMeasureApp.swift
//  OccultaMeasure
//
//  One screen: a button, the status while it runs, and the report as text that can be shared. `--autorun` starts
//  a run at launch and logs the report with NSLog, to read from the Simulator's log.
//

import SwiftUI

@MainActor
@Observable
final class MeasureModel {
    var report = ""
    var status = ""
    var running = false

    static let autorun = CommandLine.arguments.contains("--autorun")

    func run() {
        guard !self.running else { return }
        self.running = true
        self.report = ""
        UIApplication.shared.isIdleTimerDisabled = true

        Task {
            let report = await Task.detached(priority: .userInitiated) {
                Measurement.run { status in Task { @MainActor in self.status = status } }
            }.value
            self.report = report
            self.status = ""
            self.running = false
            UIApplication.shared.isIdleTimerDisabled = false
            if MeasureModel.autorun {
                // One line per entry: the log truncates a long message.
                report.split(separator: "\n", omittingEmptySubsequences: false).forEach { NSLog("%@", String($0)) }
            }
        }
    }
}

@main
struct OccultaMeasureApp: App {
    @State private var model = MeasureModel()

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Mock data and transient keys only. Nothing here touches Occulta. Keep the phone awake and unlocked; the run takes a few minutes.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)

                        Button(self.model.running ? "Running" : "Run measurements") {
                            self.model.run()
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(self.model.running)

                        if self.model.running {
                            ProgressView(self.model.status)
                        }

                        Text(self.model.report)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    .padding(16)
                }
                .navigationTitle("Occulta Measure")
                .toolbar {
                    if !self.model.report.isEmpty {
                        ShareLink(item: self.model.report)
                    }
                }
            }
            .task {
                if MeasureModel.autorun {
                    self.model.run()
                }
            }
        }
    }
}
