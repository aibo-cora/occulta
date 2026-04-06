//
//  OnboardingView.swift
//  Occulta
//

import SwiftUI

struct OnboardingView: View {
    @State private var pageIndex = 0
    @AppStorage("hasCompletedOnboarding") private var hasCompleted = false

    var body: some View {
        ZStack {
            Color(.systemBackground)
                .ignoresSafeArea()

            TabView(selection: self.$pageIndex) {
                TwoFatesScreen()
                    .tag(0)

                HowItWorksScreen()
                    .tag(1)

                TrustScreen()
                    .tag(2)

                CommitmentScreen {
                    withAnimation {
                        self.hasCompleted = true
                    }
                }
                .tag(3)
            }
            .tabViewStyle(.page(indexDisplayMode: .never))
            .animation(.easeInOut, value: self.pageIndex)

            VStack {
                HStack {
                    Spacer()
                    Button("Skip") {
                        withAnimation {
                            self.hasCompleted = true
                        }
                    }
                    .foregroundStyle(.secondary)
                    .padding()
                    .opacity(self.pageIndex < 3 ? 1 : 0)
                }

                Spacer()

                HStack(spacing: 8) {
                    ForEach(0..<4, id: \.self) { index in
                        Circle()
                            .frame(width: 8, height: 8)
                            .foregroundStyle(self.pageIndex == index ? .primary : .secondary)
                            .scaleEffect(self.pageIndex == index ? 1.2 : 1)
                            .animation(.spring(response: 0.3), value: self.pageIndex)
                    }
                }
                .padding(.bottom, 50)
            }
        }
    }
}

// MARK: - Screen 1: Same photo, two fates

private struct TwoFatesScreen: View {
    @State private var showContent = false

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            Text("You send a photo to a friend.")
                .font(.title3)
                .fontWeight(.medium)
                .multilineTextAlignment(.center)
                .padding(.bottom, 28)
                .opacity(self.showContent ? 1 : 0)
                .offset(y: self.showContent ? 0 : 12)

            HStack(alignment: .top, spacing: 16) {
                OtherAppsColumn()
                OccultaColumn()
            }
            .padding(.horizontal, 24)
            .opacity(self.showContent ? 1 : 0)
            .offset(y: self.showContent ? 0 : 20)

            Text("Same photo. Very different story.")
                .font(.subheadline)
                .fontWeight(.medium)
                .padding(.top, 24)
                .opacity(self.showContent ? 1 : 0)

            Spacer()
        }
        .onAppear {
            withAnimation(.easeOut(duration: 0.6).delay(0.3)) {
                self.showContent = true
            }
        }
    }
}

private struct OtherAppsColumn: View {
    private let violations = [
        "Facial recognition",
        "Location extracted",
        "Content classified",
        "Stored indefinitely",
        "Used for ad targeting"
    ]

    var body: some View {
        VStack(spacing: 0) {
            Text("OTHER APPS")
                .font(.caption2)
                .fontWeight(.medium)
                .foregroundStyle(.secondary)
                .tracking(1)
                .padding(.bottom, 10)

            VStack(alignment: .leading, spacing: 10) {
                // Visible photo representation
                RoundedRectangle(cornerRadius: 8)
                    .fill(.quaternary)
                    .frame(height: 56)
                    .overlay {
                        Text("visible")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }

                ForEach(self.violations, id: \.self) { violation in
                    HStack(spacing: 6) {
                        Circle()
                            .fill(.red.opacity(0.8))
                            .frame(width: 5, height: 5)

                        Text(violation)
                            .font(.caption2)
                            .foregroundStyle(.red.opacity(0.7))
                    }
                }
            }
            .padding(12)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
        }
    }
}

private struct OccultaColumn: View {
    private let protections = [
        "Encrypted on device",
        "No metadata exposed",
        "Only recipient can open"
    ]

    var body: some View {
        VStack(spacing: 0) {
            Text("OCCULTA")
                .font(.caption2)
                .fontWeight(.medium)
                .foregroundStyle(.teal)
                .tracking(1)
                .padding(.bottom, 10)

            VStack(alignment: .leading, spacing: 10) {
                // Encrypted photo representation
                RoundedRectangle(cornerRadius: 8)
                    .fill(.teal.opacity(0.1))
                    .frame(height: 56)
                    .overlay {
                        HStack(spacing: 3) {
                            ForEach(Array([0.3, 0.5, 0.2, 0.6, 0.4].enumerated()), id: \.offset) { _, opacity in
                                RoundedRectangle(cornerRadius: 2)
                                    .fill(.teal.opacity(opacity))
                                    .frame(width: 6, height: 6)
                            }
                        }
                    }
                    .overlay {
                        RoundedRectangle(cornerRadius: 8)
                            .strokeBorder(.teal.opacity(0.3), lineWidth: 1)
                    }

                ForEach(self.protections, id: \.self) { protection in
                    HStack(spacing: 6) {
                        Circle()
                            .fill(.teal)
                            .frame(width: 5, height: 5)

                        Text(protection)
                            .font(.caption2)
                            .foregroundStyle(.teal)
                    }
                }
            }
            .padding(12)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
        }
    }
}

// MARK: - Screen 2: How it works

private struct HowItWorksScreen: View {
    @State private var visibleStep = -1

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            Text("How it works")
                .font(.title2)
                .fontWeight(.medium)
                .padding(.bottom, 28)

            VStack(spacing: 14) {
                StepCard(
                    number: "1",
                    title: "Collect keys in person",
                    description: "Walk up to someone. Phones exchange cryptographic keys via UWB — 25 cm range. No server involved.",
                    accentColor: .purple,
                    isVisible: self.visibleStep >= 0
                )

                StepCard(
                    number: "2",
                    title: "Encrypt anything for them",
                    description: "Photos, files, documents — sealed with a key derived from their public key. Only their device can open it.",
                    accentColor: .teal,
                    isVisible: self.visibleStep >= 1
                )

                StepCard(
                    number: "3",
                    title: "Send it however you want",
                    description: "Email, AirDrop, iMessage, anything. Security lives in the key, not the channel.",
                    accentColor: .orange,
                    isVisible: self.visibleStep >= 2
                )
            }
            .padding(.horizontal, 28)

            Spacer()
            Spacer()
        }
        .onAppear {
            for i in 0...2 {
                withAnimation(.spring(response: 0.5, dampingFraction: 0.8).delay(Double(i) * 0.3 + 0.2)) {
                    self.visibleStep = i
                }
            }
        }
    }
}

private struct StepCard: View {
    let number: String
    let title: String
    let description: String
    let accentColor: Color
    let isVisible: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            ZStack {
                Circle()
                    .strokeBorder(self.accentColor, lineWidth: 1.5)
                    .frame(width: 26, height: 26)

                Text(self.number)
                    .font(.caption)
                    .fontWeight(.medium)
                    .foregroundStyle(self.accentColor)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(self.title)
                    .font(.subheadline)
                    .fontWeight(.medium)

                Text(self.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 0)
        }
        .padding(14)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 14))
        .overlay(alignment: .leading) {
            RoundedRectangle(cornerRadius: 14)
                .fill(self.accentColor)
                .frame(width: 3)
        }
        .opacity(self.isVisible ? 1 : 0)
        .offset(x: self.isVisible ? 0 : 40)
    }
}

// MARK: - Screen 3: Trust

private struct TrustScreen: View {
    @State private var showContent = false

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            VStack(spacing: 6) {
                Text("Why you can trust this")
                    .font(.title2)
                    .fontWeight(.medium)

                Text("Not promises — architecture.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .padding(.bottom, 28)
            .opacity(self.showContent ? 1 : 0)

            VStack(spacing: 14) {
                TrustRow(
                    icon: "cpu.fill",
                    title: "Secure Enclave",
                    description: "Your private key lives in hardware. It never leaves the chip — not in memory, not on disk, not in backups.",
                    accentColor: .teal
                )

                TrustRow(
                    icon: "network.slash",
                    title: "No network. Ever.",
                    description: "Zero servers. Zero accounts. Zero phone numbers. Nothing to hack, subpoena, or shut down.",
                    accentColor: .orange
                )

                TrustRow(
                    icon: "curlybraces",
                    title: "Fully open source",
                    description: "Apache 2.0. Every line of cryptographic code is public. Don't take our word for it — read it.",
                    accentColor: .purple
                )
                
                TrustRow(icon: "envelope.badge.shield.half.filled.fill", title: "Quantum Protection", description: "ML-KEM1024 algorithm protecting your messages from quantum attacks.", accentColor: .blue)
            }
            .padding(.horizontal, 28)
            .opacity(self.showContent ? 1 : 0)
            .offset(y: self.showContent ? 0 : 16)

            Spacer()
            Spacer()
        }
        .onAppear {
            withAnimation(.easeOut(duration: 0.5).delay(0.2)) {
                self.showContent = true
            }
        }
    }
}

private struct TrustRow: View {
    let icon: String
    let title: String
    let description: String
    let accentColor: Color

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: self.icon)
                .font(.title3)
                .foregroundStyle(self.accentColor)
                .frame(width: 40, height: 40)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 10))

            VStack(alignment: .leading, spacing: 3) {
                Text(self.title)
                    .font(.subheadline)
                    .fontWeight(.medium)

                Text(self.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 0)
        }
        .padding(14)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 14))
    }
}

// MARK: - Screen 4: Commitment

private struct CommitmentScreen: View {
    let onComplete: () -> Void

    @State private var showContent = false
    @State private var ringRotation = 0.0

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            // Concentric rings
            ZStack {
                ForEach(0..<3, id: \.self) { i in
                    Circle()
                        .strokeBorder(.primary.opacity(0.06 + Double(i) * 0.04), lineWidth: 1)
                        .frame(width: CGFloat(80 - i * 14), height: CGFloat(80 - i * 14))
                }

                Circle()
                    .strokeBorder(.teal, lineWidth: 1.5)
                    .frame(width: 28, height: 28)
                    .overlay {
                        Circle()
                            .fill(.teal)
                            .frame(width: 8, height: 8)
                    }
            }
            .rotationEffect(.degrees(self.ringRotation))
            .padding(.bottom, 36)
            .opacity(self.showContent ? 1 : 0)

            VStack(spacing: 10) {
                Text("Meet someone.\nOwn the connection.")
                    .font(.title)
                    .fontWeight(.semibold)
                    .multilineTextAlignment(.center)

                Text("No company holds a copy.\nNo legal process can retrieve\nwhat was never stored.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal, 40)
            .opacity(self.showContent ? 1 : 0)
            .offset(y: self.showContent ? 0 : 12)

            Spacer()

            Button {
                self.onComplete()
            } label: {
                Text("I'm ready")
                    .fontWeight(.medium)
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .tint(.primary)
            .foregroundStyle(Color(.systemBackground))
            .padding(.horizontal, 40)
            .padding(.bottom, 100)
            .opacity(self.showContent ? 1 : 0)
        }
        .onAppear {
            withAnimation(.easeOut(duration: 0.6).delay(0.2)) {
                self.showContent = true
            }
            withAnimation(.linear(duration: 30).repeatForever(autoreverses: false)) {
                self.ringRotation = 360
            }
        }
    }
}

// MARK: - Preview

#Preview {
    OnboardingView()
}
