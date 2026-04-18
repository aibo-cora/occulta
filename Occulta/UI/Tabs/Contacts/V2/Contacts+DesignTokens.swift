//
//  Contacts+DesignTokens.swift
//  Occulta
//

import SwiftUI

// MARK: - Color Tokens

extension Color {
    static let occultaAccent   = Color(red: 0xD3/255, green: 0x4F/255, blue: 0x2C/255)
    static let occultaVerified = Color(red: 0x2E/255, green: 0x7D/255, blue: 0x5B/255)
    static let occultaWarn     = Color(red: 0xC0/255, green: 0x8A/255, blue: 0x2B/255)
    static let occultaDanger   = Color(red: 0xD0/255, green: 0x48/255, blue: 0x40/255)
}

// MARK: - Verification Status

enum VerificationStatus {
    case verified, unverified, pending

    var color: Color {
        switch self {
        case .verified:  .occultaVerified
        case .unverified: .occultaWarn
        case .pending:   .secondary
        }
    }

    var chipLabel: String {
        switch self {
        case .verified:   "✓ VERIFIED"
        case .unverified: "! UNVERIFIED"
        case .pending:    "… PENDING"
        }
    }

    var sectionLabel: String {
        switch self {
        case .verified:   "VERIFIED"
        case .unverified: "UNVERIFIED"
        case .pending:    "PENDING EXCHANGE"
        }
    }
}

// MARK: - Avatar Gradient

func avatarGradientV2(for id: String) -> LinearGradient {
    let hash = id.unicodeScalars.reduce(0) { ($0 &* 31) &+ Int($1.value) }
    let hue  = Double(abs(hash) % 360) / 360.0
    let hue2 = (hue + 30.0 / 360.0).truncatingRemainder(dividingBy: 1.0)
    return LinearGradient(
        colors: [
            Color(hue: hue,  saturation: 0.62, brightness: 0.58),
            Color(hue: hue2, saturation: 0.56, brightness: 0.44)
        ],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
}

// MARK: - Contact.Profile computed helpers

extension Contact.Profile {
    var verificationStatus: VerificationStatus {
        let keys = contactPublicKeys
        guard let keys, !keys.isEmpty, keys.last?.expiredOn == nil else { return .pending }
        let ownerHash = try? Manager.Crypto().decrypt(data: keys.last?.owner)
        let ourHash   = (try? Manager.Key().retrieveIdentity())?.sha256
        guard let ownerHash, let ourHash, !ownerHash.isEmpty else { return .unverified }
        return ownerHash == ourHash ? .verified : .unverified
    }

    var fingerprintPreview: String? {
        guard
            let material  = contactPublicKeys?.last?.material,
            let decrypted = material.decrypt()
        else { return nil }
        let hex    = decrypted.sha256.map { String(format: "%02X", $0) }
        let first  = hex.prefix(8).joined(separator: " ")
        let second = hex.dropFirst(8).prefix(8).joined(separator: " ")
        return "\(first) · \(second)…"
    }

    var fingerprintFull: String? {
        guard
            let material  = contactPublicKeys?.last?.material,
            let decrypted = material.decrypt()
        else { return nil }
        return decrypted.sha256.map { String(format: "%02X", $0) }.joined(separator: " ")
    }

    var freshnessLabel: String {
        guard
            let acquiredData = contactPublicKeys?.last?.acquiredAt,
            let decrypted    = acquiredData.decrypt(),
            let str          = String(data: decrypted, encoding: .utf8),
            let interval     = Double(str)
        else {
            return (contactPublicKeys?.isEmpty ?? true) ? "pending" : "never"
        }
        let date = Date(timeIntervalSince1970: interval)
        let days = Calendar.current.dateComponents([.day], from: date, to: .now).day ?? 0
        if days == 0 { return "today" }
        if days < 31 { return "\(days)d" }
        return "\(days / 30)mo"
    }

    var exchangedDateLabel: String {
        guard
            let acquiredData = contactPublicKeys?.last?.acquiredAt,
            let decrypted    = acquiredData.decrypt(),
            let str          = String(data: decrypted, encoding: .utf8),
            let interval     = Double(str)
        else { return "unknown" }
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        return formatter.string(from: Date(timeIntervalSince1970: interval))
    }

    var encryptionSchemeLabel: String {
        contactPublicKeys?.last?.quantumKeyMaterialEncrypted != nil
            ? "Hybrid PQ · ML-KEM-1024"
            : "Classical (v1)"
    }
}
