//
//  KeychainAvailability.swift
//  OccultaTests
//
//  Whether the test host can store Keychain items, for tests that store real ones without an Enclave key.
//
//  `secureEnclaveAvailable()` doesn't cover them: those tests write generic-password items (the tier secrets, the tier
//  PQ records, share staging's items in the App Group) on accounts of their own, and some reach no Enclave at all. They
//  need a Keychain, not an Enclave. CI builds with `CODE_SIGNING_ALLOWED=NO`, so its test host has no entitlements and
//  every `SecItem` call there returns `errSecMissingEntitlement` (-34018). Gated on this, those tests show as skipped
//  there, as the Enclave tests do, and run everywhere a Keychain works, the Simulator included.
//

import Foundation
import Security

/// True if a throwaway generic-password item can be added, in the host's default access group or in `accessGroup`. The
/// item is deleted again.
func keychainAvailable(accessGroup: String? = nil) -> Bool {
    var query: [String: Any] = [
        kSecClass as String:       kSecClassGenericPassword,
        kSecAttrAccount as String: "test.keychain.probe.\(UUID().uuidString)"
    ]
    if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }

    var attributes = query
    attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    attributes[kSecValueData as String] = Data([0])

    guard SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess else { return false }
    SecItemDelete(query as CFDictionary)
    return true
}

/// `keychainAvailable` in the App Group the app shares with the share extension, where share staging keeps `r_S` and
/// its PQ record.
func sharedKeychainAvailable() -> Bool {
    keychainAvailable(accessGroup: "group.com.occulta.shared")
}
