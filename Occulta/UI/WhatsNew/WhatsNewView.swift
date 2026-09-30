//
//  WhatsNewView.swift
//  Occulta
//

import SwiftUI

/// Full-page release notes. Not a sheet: `RootView` swaps it in for the tab content, the way it
/// does `OnboardingView`, so it can never collide with another modal presenting at unlock.
///
/// Also pushed from Settings, where there is a back button and nothing to acknowledge: pass no
/// `onContinue` and the Continue button is left out.
struct WhatsNewView: View {

    let release: WhatsNew.Release
    var onContinue: (() -> Void)? = nil

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 32) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("What's New")
                        .font(.largeTitle)
                        .fontWeight(.bold)

                    Text("Version \(self.release.version)")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
                .accessibilityAddTraits(.isHeader)

                if !self.release.features.isEmpty {
                    VStack(alignment: .leading, spacing: 24) {
                        ForEach(self.release.features, id: \.title) { feature in
                            FeatureRow(feature: feature)
                        }
                    }
                }

                if !self.release.fixes.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("FIXES")
                            .font(.caption2)
                            .fontWeight(.medium)
                            .foregroundStyle(.secondary)
                            .tracking(1)
                            .accessibilityAddTraits(.isHeader)

                        ForEach(Array(self.release.fixes.enumerated()), id: \.offset) { _, fix in
                            HStack(alignment: .firstTextBaseline, spacing: 10) {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(.teal)
                                    .accessibilityHidden(true)

                                Text(fix)
                                    .font(.subheadline)
                            }
                            .accessibilityElement(children: .combine)
                        }
                    }
                }
            }
            .padding(.horizontal, 24)
            .padding(.top, self.onContinue == nil ? 8 : 48)
            .padding(.bottom, 24)
            .frame(maxWidth: 600, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .safeAreaInset(edge: .bottom) {
            if let onContinue = self.onContinue {
                Button {
                    onContinue()
                } label: {
                    Text("Continue")
                        .frame(maxWidth: 600)
                }
                .prominentButtonStyle()
                .controlSize(.large)
                .padding(.horizontal, 24)
                .padding(.vertical, 12)
                .frame(maxWidth: .infinity)
                .background(.bar)
            }
        }
        .background(Color(.systemBackground).ignoresSafeArea())
    }
}

private struct FeatureRow: View {

    let feature: WhatsNew.Feature

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: self.feature.symbol)
                .font(.title2)
                .foregroundStyle(.teal)
                .frame(minWidth: 36)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text(self.feature.title)
                    .font(.headline)

                Text(self.feature.detail)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

#Preview {
    WhatsNewView(
        release: WhatsNew.Release(
            version: "9.9.9",
            features: [
                WhatsNew.Feature(symbol: "sparkles", title: "A new thing", detail: "What it does for you, in a sentence or two."),
                WhatsNew.Feature(symbol: "bolt.fill", title: "Another new thing", detail: "A second line of detail, long enough to wrap onto a second line on a phone.")
            ],
            fixes: [
                "Fixed a problem that could cause something to go wrong.",
                "Fixed a second, shorter problem."
            ]
        ),
        onContinue: { }
    )
}
