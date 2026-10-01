//
//  OnboardingView.swift
//  Occulta
//
//  First-launch introduction, in the key exchange's visual language: black, the particle field, mono
//  step labels. Shown once, before any PIN or depth exists, and it writes nothing but
//  `hasCompletedOnboarding`, a flag every install carries.
//

import SwiftUI

struct OnboardingView: View {
    @AppStorage("hasCompletedOnboarding") private var hasCompleted = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private let pages = Page.pages(secureModeEnabled: FeatureFlags.isEnabled(.secureMode))
    @State private var current: Page = .welcome

    private var currentIndex: Int {
        self.pages.firstIndex(of: self.current) ?? 0
    }

    private var isLastPage: Bool {
        self.currentIndex == self.pages.count - 1
    }

    var body: some View {
        ZStack {
            Color.black
                .ignoresSafeArea()

            // The exchange screen's backdrop, so a first real exchange looks familiar. Left out under
            // Reduce Motion, since the field never stops moving.
            if !self.reduceMotion {
                ParticleFieldView(phase: self.current.particlePhase, directionXY: nil, distance: nil)
                    // Faded where the text sits.
                    .mask {
                        LinearGradient(
                            stops: [
                                .init(color: .white, location: 0),
                                .init(color: .white, location: 0.45),
                                .init(color: .white.opacity(0.12), location: 0.7)
                            ],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    }
                    .opacity(0.6)
                    .ignoresSafeArea()
                    .allowsHitTesting(false)
                    .accessibilityHidden(true)
            }

            // Continue only, no Skip: Skip let people past the 25 cm requirement without seeing it
            // (`Friction/USER_ENGAGEMENT_FRICTION.md`, M3).
            TabView(selection: self.$current) {
                ForEach(Array(self.pages.enumerated()), id: \.element) { index, page in
                    PageView(page: page, number: index + 1, isCurrent: page == self.current)
                        .tag(page)
                }
            }
            .tabViewStyle(.page(indexDisplayMode: .never))
        }
        .safeAreaInset(edge: .bottom) {
            self.controls
        }
        .preferredColorScheme(.dark)
    }

    private var controls: some View {
        VStack(spacing: 20) {
            StepPills(count: self.pages.count, current: self.currentIndex)

            Button {
                self.advance()
            } label: {
                Text(self.isLastPage ? "Get started" : "Continue")
                    .fontWeight(.semibold)
                    .frame(maxWidth: .infinity)
            }
            .prominentButtonStyle()
            .tint(.occultaAccent)
            .controlSize(.large)
        }
        .padding(.horizontal, 28)
        .padding(.top, 12)
        .padding(.bottom, 8)
    }

    private func advance() {
        guard !self.isLastPage else {
            withAnimation {
                self.hasCompleted = true
            }
            return
        }

        withAnimation(self.reduceMotion ? nil : .easeInOut) {
            self.current = self.pages[self.currentIndex + 1]
        }
    }
}

// MARK: - Pages

extension OnboardingView {

    /// One screen. The copy is kept here, apart from the drawing, so tests can hold the flow to what
    /// other documents require of it.
    enum Page: CaseIterable, Identifiable {
        case welcome, meet, sendAnywhere, secureMode, vault

        var id: Self { self }

        /// The pages this build shows, in order.
        ///
        /// Secure Mode appears only with the feature on, because its page sends people to
        /// Settings › Security, which exists only then. Vault stays last: it ends on something usable
        /// with no contacts at all (`USER_ENGAGEMENT_FRICTION.md`, C1), and it carries the pointer to
        /// Restore from Backup that `decisions.md` requires ("Restore discoverability").
        static func pages(secureModeEnabled: Bool) -> [Page] {
            self.allCases.filter { $0 != .secureMode || secureModeEnabled }
        }

        /// Shown upper-cased after the step number; VoiceOver reads it as written.
        var label: String {
            switch self {
            case .welcome:      "Occulta"
            case .meet:         "Meet"
            case .sendAnywhere: "Send anywhere"
            case .secureMode:   "Secure Mode"
            case .vault:        "Vault"
            }
        }

        var title: String {
            switch self {
            case .welcome:      "Contacts you've actually met."
            case .meet:         "Hold your phones together."
            case .sendAnywhere: "Any app can carry it. None can read it."
            case .secureMode:   "If someone makes you unlock it."
            case .vault:        "Some things are just for you."
            }
        }

        var message: String {
            switch self {
            case .welcome:
                "Your identity is a key that lives in this iPhone's Secure Enclave and never leaves it."
            case .meet:
                "Within 25 cm, they trade keys directly, with no server in between."
            case .sendAnywhere:
                "Seal a photo, file, or note for someone, then send it with Messages, Mail, or AirDrop. Only their phone can open it."
            case .secureMode:
                "Set a second PIN. It opens Occulta with the contacts you choose, and your vault, hidden."
            case .vault:
                "The Vault keeps notes, seed phrases, and keys sealed on this iPhone. You don't need any contacts to use it."
            }
        }

        var footnote: String {
            switch self {
            case .welcome:
                "Open source, so anyone can check how it works."
            case .meet:
                "Both phones need ultra-wideband."
            case .sendAnywhere:
                "Post-quantum protection when both phones run iOS 26 or later."
            case .secureMode:
                // The limit is stated because the protection is the app's filtering, not separate
                // keys (README, Secure Mode).
                "Set it up in Settings › Security. It stops someone using the app, not someone copying data off the phone."
            case .vault:
                "Back it up by splitting a key among people you trust. On a new phone, restore it from the + menu in the Vault tab."
            }
        }

        /// `ParticleCanvas` mode behind the page: scattered (0), lattice (3) or settled (5). Only the
        /// modes that spread across the screen; converging, orbit and rings gather at its centre,
        /// under the page's drawing, and settled keeps whatever clump the previous page left.
        var particlePhase: Int {
            switch self {
            case .welcome:      0
            case .meet:         5
            case .sendAnywhere: 3
            case .secureMode:   0
            case .vault:        5
            }
        }
    }
}

// MARK: - Page

private struct PageView: View {
    let page: OnboardingView.Page
    let number: Int
    let isCurrent: Bool

    var body: some View {
        GeometryReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    Text(String(format: "%02d · %@", self.number, self.page.label))
                        .font(.system(.caption2, design: .monospaced, weight: .semibold))
                        .kerning(2)
                        .textCase(.uppercase)
                        .foregroundStyle(.white.opacity(0.5))
                        .accessibilityLabel(self.page.label)

                    Spacer(minLength: 32)

                    PageVisual(page: self.page, isCurrent: self.isCurrent)
                        .frame(maxWidth: .infinity)
                        .accessibilityHidden(true)

                    Spacer(minLength: 32)

                    VStack(alignment: .leading, spacing: 12) {
                        Text(self.page.title)
                            .font(.title.weight(.semibold))
                            .foregroundStyle(.white)

                        Text(self.page.message)
                            .foregroundStyle(.white.opacity(0.7))

                        Text(self.page.footnote)
                            .font(.footnote)
                            .foregroundStyle(.white.opacity(0.5))
                            .padding(.top, 4)
                    }
                    .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.horizontal, 28)
                .padding(.vertical, 20)
                // Fills the page when the text fits; scrolls at large text sizes instead of clipping.
                .frame(maxWidth: .infinity, minHeight: proxy.size.height, alignment: .topLeading)
                .accessibilityElement(children: .combine)
            }
            .scrollBounceBehavior(.basedOnSize)
            .scrollIndicators(.hidden)
        }
    }
}

private struct PageVisual: View {
    let page: OnboardingView.Page
    let isCurrent: Bool

    var body: some View {
        switch self.page {
        case .welcome:      ZeroCounts()
        case .meet:         ProximityDemo(isCurrent: self.isCurrent)
        case .sendAnywhere: SealedInTransit()
        case .secureMode:   TwoPINs()
        case .vault:        SealedEntries()
        }
    }
}

// MARK: - Visuals

private struct ZeroCounts: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ForEach(["servers", "accounts", "phone numbers"], id: \.self) { noun in
                HStack(alignment: .firstTextBaseline, spacing: 16) {
                    Text("0")
                        .font(.system(.largeTitle, design: .monospaced, weight: .bold))
                        .foregroundStyle(Color.occultaAccent)

                    Text(noun)
                        .font(.title3)
                        .foregroundStyle(.white)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Counts down to the 25 cm the exchange requires, each time the page comes into view.
private struct ProximityDemo: View {
    let isCurrent: Bool

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var distance = ProximityRing.startDistance

    var body: some View {
        ProximityRing(distance: self.distance)
            .onChange(of: self.isCurrent, initial: true) { _, isCurrent in
                guard isCurrent else {
                    self.distance = ProximityRing.startDistance
                    return
                }

                withAnimation(self.reduceMotion ? nil : .easeInOut(duration: 2.4).delay(0.4)) {
                    self.distance = ProximityRing.exchangeDistance
                }
            }
    }
}

/// The exchange screen's distance ring. `Animatable`, so the readout counts through every
/// centimetre rather than jumping to the end.
private struct ProximityRing: View, Animatable {
    static let startDistance    = 0.80
    static let exchangeDistance = 0.25

    var distance: Double

    var animatableData: Double {
        get { self.distance }
        set { self.distance = newValue }
    }

    private var progress: Double {
        let span = Self.startDistance - Self.exchangeDistance
        return min(1, max(0, (Self.startDistance - self.distance) / span))
    }

    var body: some View {
        let isClose = self.distance <= Self.exchangeDistance + 0.005
        let tint: Color = isClose ? .occultaVerified : .occultaAccent

        ZStack {
            Circle()
                .stroke(.white.opacity(0.08), lineWidth: 8)

            Circle()
                .trim(from: 0, to: self.progress)
                .stroke(tint, style: StrokeStyle(lineWidth: 8, lineCap: .round))
                .rotationEffect(.degrees(-90))

            VStack(spacing: 2) {
                Text("\(Int((self.distance * 100).rounded()))")
                    .font(.system(size: 34, weight: .bold, design: .monospaced))
                    .foregroundStyle(isClose ? Color.occultaVerified : .white)

                Text("cm")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.5))
            }
        }
        .frame(width: 150, height: 150)
    }
}

private struct SealedInTransit: View {
    var body: some View {
        VStack(spacing: 22) {
            HStack(spacing: 30) {
                ForEach(["message.fill", "envelope.fill", "square.and.arrow.up.fill"], id: \.self) { symbol in
                    Image(systemName: symbol)
                }
            }
            .font(.title2)
            .foregroundStyle(.white.opacity(0.4))

            HStack(spacing: 10) {
                Image(systemName: "lock.fill")
                    .foregroundStyle(Color.occultaAccent)

                Text("A7F3 9C1E 04BD 5E82")
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(Color.occultaVerified)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .overlay {
                Capsule()
                    .strokeBorder(.white.opacity(0.15), lineWidth: 1)
            }
        }
    }
}

/// Same app, two PINs. The second view just has fewer rows: a hidden contact leaves no gap in the
/// real list, so the drawing doesn't show one either.
private struct TwoPINs: View {
    var body: some View {
        HStack(alignment: .top, spacing: 36) {
            MiniPhone(rows: 4, caption: "PIN", captionColor: .white.opacity(0.5))
            MiniPhone(rows: 2, caption: "SECOND PIN", captionColor: .occultaAccent)
        }
    }
}

private struct MiniPhone: View {
    let rows: Int
    let caption: String
    let captionColor: Color

    var body: some View {
        VStack(spacing: 12) {
            RoundedRectangle(cornerRadius: 14)
                .strokeBorder(.white.opacity(0.25), lineWidth: 1)
                .frame(width: 80, height: 140)
                .overlay(alignment: .top) {
                    VStack(spacing: 10) {
                        ForEach(0..<self.rows, id: \.self) { _ in
                            HStack(spacing: 6) {
                                Circle()
                                    .frame(width: 10, height: 10)

                                Capsule()
                                    .frame(height: 6)
                            }
                        }
                    }
                    .foregroundStyle(.white.opacity(0.5))
                    .padding(.horizontal, 12)
                    .padding(.top, 20)
                }

            Text(self.caption)
                .font(.system(.caption2, design: .monospaced, weight: .semibold))
                .kerning(1.5)
                .foregroundStyle(self.captionColor)
        }
    }
}

private struct SealedEntries: View {
    var body: some View {
        VStack(spacing: 10) {
            ForEach(["Seed phrase", "Backup codes", "Notes"], id: \.self) { label in
                HStack(spacing: 12) {
                    Image(systemName: "lock.fill")
                        .foregroundStyle(Color.occultaAccent)

                    Text(label)
                        .foregroundStyle(.white)

                    Spacer()

                    Text("••••••")
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.white.opacity(0.35))
                }
                .font(.subheadline)
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
                .background(.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
            }
        }
    }
}

// MARK: - Step pills

/// The exchange screen's step indicator.
private struct StepPills: View {
    let count: Int
    let current: Int

    var body: some View {
        HStack(spacing: 6) {
            ForEach(0..<self.count, id: \.self) { index in
                Capsule()
                    .fill(self.color(for: index))
                    .frame(width: index == self.current ? 40 : 24, height: 4)
            }
        }
        .animation(.easeInOut(duration: 0.3), value: self.current)
        .accessibilityElement()
        .accessibilityLabel("Page \(self.current + 1) of \(self.count)")
    }

    private func color(for index: Int) -> Color {
        if index == self.current { return .occultaAccent }

        return .white.opacity(index < self.current ? 0.45 : 0.15)
    }
}

// MARK: - Preview

#Preview {
    OnboardingView()
}
