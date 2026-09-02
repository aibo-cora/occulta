import SwiftData
import Contacts
import Foundation
import CryptoKit

// MARK: - Main Contact Model

enum Contact { }

extension Contact {
    @Model
    final class Profile {
        var identifier: String = ""
        
        var givenName: String = ""
        var familyName: String = ""
        var middleName: String = ""
        var namePrefix: String = ""
        var nameSuffix: String = ""
        var nickname: String = ""
        
        var organizationName: String = ""
        var departmentName: String = ""
        var jobTitle: String = ""
        
        var phoneticGivenName: String = ""
        var phoneticMiddleName: String = ""
        var phoneticFamilyName: String = ""
        
        var birthday: String?
        var note: String = ""
        
        var thumbnailImageData: Data?
        var imageData: Data?
        
        @Relationship(deleteRule: .cascade, inverse: \PhoneNumber.profile)
        var phoneNumbers: [PhoneNumber]? = []
        
        @Relationship(deleteRule: .cascade, inverse: \EmailAddress.profile)
        var emailAddresses: [EmailAddress]? = []
        
        @Relationship(deleteRule: .cascade, inverse: \PostalAddress.profile)
        var postalAddresses: [PostalAddress]? = []
        
        @Relationship(deleteRule: .cascade, inverse: \URLAddress.profile)
        var urlAddresses: [URLAddress]? = []
        
        // MARK: Application specific metadata - encrypted
        
        @Relationship(deleteRule: .cascade, inverse: \Key.profile)
        /// Public key of the trusted contact.
        var contactPublicKeys: [Key]? = []
        /// Encrypted forward secrecy metadata.
        var forwardSecrecyEncrypted: Data?

        /// Encrypted JSON-encoded [SignedAttribute] blob (Issue #6).
        /// nil until the contact has shared at least one signed attribute.
        /// SwiftData lightweight migration: new optional column, no plan required.
        var signedAttributes: Data? = nil
        
        /// Tracks which encryption scheme protects this record's fields.
        /// Default is 1 (v1_identityDerived) for backward compatibility with
        /// existing records. Migration sets this to 2 (v2_hybridPQ).
        ///
        /// SwiftData handles the schema addition automatically — new column
        /// with a default value is a lightweight migration.
        var encryptionScheme: Int = EncryptionScheme.v1_identityDerived.rawValue

        /// Non-nil means this contact has been soft-deleted. The field is encrypted;
        /// only its nil/non-nil status is meaningful at the query layer. Content is
        /// a fixed sentinel — no date or identity information is stored here.
        /// Soft-deleted rows are never shown in any view. Cap: 50 rows; when full,
        /// one existing soft-deleted row is hard-deleted before a new one is written.
        /// Named `deletionToken` (not `isDeleted`) to avoid shadowing NSManagedObject.isDeleted.
        var deletionToken: Data? = nil

        /// Encrypted depth-visibility (fixed-width plaintext, via `DepthCodec`):
        ///   Int.max — always visible (default for all new contacts)
        ///   0       — hidden at all duress depths
        ///   N       — visible through duress depth N, hidden at N+1 and deeper
        /// Every value encodes to exactly two bytes, so the sealed column is 30 bytes
        /// whichever one is stored. That is a security property rather than an incidental
        /// one: AES-GCM does not pad, so a variable-length plaintext makes the column
        /// length a keyless classifier over safe versus hidden contacts — which is what
        /// the previous JSON encoding did, for every row, until Bug 85.
        /// Always non-nil after creation (Contact+Manager.swift) or the legacy backfill
        /// migration — nil is not a valid steady state; see forensic-trace-avoidance.md S6.
        var visibleThroughDepth: Data? = nil

        /// Encrypted global-trustee depth stamp (encrypted JSON Int), exact-match — not a
        /// ceiling, unlike visibleThroughDepth:
        ///   -1 — not a global trustee at the current depth (default for all new contacts)
        ///   N  — marked a global trustee at exactly depth N; not surfaced at any other depth
        /// Exact-match (mirroring VaultEntry.visibleThroughDepth) so a trustee designation
        /// made under duress can never leak into the real depth-0 suggestion list or vice
        /// versa. Always non-nil after creation or the backfill migration — nil is not a
        /// valid steady state, same invariant as visibleThroughDepth.
        var globalTrusteeDepth: Data? = nil

        /// Encrypted UInt8 — maximum bundle version this contact's app can decode.
        /// nil = unknown, treat as v3fs on send. Derived from `appVersion` in received bundles.
        /// SwiftData lightweight migration: new optional column, no plan required.
        var maxBundleVersion: Data? = nil

        /// Encrypted duress-origin depth stamp (encrypted JSON Int), floor — not a ceiling,
        /// and not exact-match either:
        ///   0 — created at the real depth (default for all new contacts); no confinement,
        ///       defer entirely to visibleThroughDepth's ceiling for visibility.
        ///   N — created while already at duress depth N; visible at N and every depth
        ///       nested deeper than N, hidden at any depth shallower than N (including 0).
        /// Why a floor and not exact-match: a contact born under coercion has to keep
        /// working normally if the operator goes deeper into another nested layer after
        /// it was created — exact-match would make it start rejecting bundles again the
        /// moment depth passes N, reproducing the exact duress-detection tell this field
        /// exists to remove (see Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md).
        /// Why sensitivity classification is bypassed entirely for these contacts (see
        /// isVisible below): there is nothing real behind a contact the coercer created
        /// themselves — they already know everything about it — so there is no protective
        /// purpose in ever hiding it again, and doing so would only reopen the same tell.
        /// Always non-nil after creation or the backfill migration — nil is not a valid
        /// steady state, same invariant as visibleThroughDepth/globalTrusteeDepth.
        var originDepth: Data? = nil

        // MARK: - Full Designated Initializer
        
        init(
            identifier: String,
            givenName: String,
            familyName: String,
            middleName: String,
            namePrefix: String = "",
            nameSuffix: String = "",
            nickname: String,
            organizationName: String,
            departmentName: String,
            jobTitle: String,
            phoneticGivenName: String = "",
            phoneticMiddleName: String = "",
            phoneticFamilyName: String = "",
            birthday: String? = nil,
            note: String = "",
            imageData: Data? = nil,
            thumbnailImageData: Data? = nil,
            phoneNumbers: [PhoneNumber] = [],
            emailAddresses: [EmailAddress] = [],
            postalAddresses: [PostalAddress] = [],
            urlAddresses: [URLAddress] = [],
            encryptionScheme: Int = EncryptionScheme.v1_identityDerived.rawValue
        ) {
            self.identifier = identifier
            self.givenName = givenName
            self.familyName = familyName
            self.middleName = middleName
            self.namePrefix = namePrefix
            self.nameSuffix = nameSuffix
            self.nickname = nickname
            self.organizationName = organizationName
            self.departmentName = departmentName
            self.jobTitle = jobTitle
            self.phoneticGivenName = phoneticGivenName
            self.phoneticMiddleName = phoneticMiddleName
            self.phoneticFamilyName = phoneticFamilyName
            self.birthday = birthday
            self.note = note
            self.imageData = imageData
            self.thumbnailImageData = thumbnailImageData
            self.phoneNumbers = phoneNumbers
            self.emailAddresses = emailAddresses
            self.postalAddresses = postalAddresses
            self.urlAddresses = urlAddresses
            self.encryptionScheme = encryptionScheme
        }
        
        var fullName: String {
            PersonNameComponents(
                namePrefix: self.namePrefix,
                givenName: self.givenName,
                middleName: self.middleName,
                familyName: self.familyName,
                nameSuffix: self.nameSuffix,
                nickname: self.nickname
            ).formatted(.name(style: .long))
        }
    }
}

// MARK: - Depth visibility

extension Contact.Profile {
    /// Visible at `depth`. Ceiling semantics: a contact stamped N is visible at every
    /// depth 0...N. Canonical definition — every caller needing "is this contact visible"
    /// goes through this or the `usingKey:` sibling below.
    ///
    /// Duress-origin contacts (originDepth > 0) short-circuit this entirely and use floor
    /// semantics instead — visible at their origin depth and everything nested deeper,
    /// never composed with the ceiling below. See originDepth's doc comment for why.
    ///
    /// originDepth's three possible states are handled differently, deliberately:
    ///   - absent (nil): pre-backfill, or genuinely real — falls through to the ceiling
    ///     check below. Safe: a real contact was never protected by this field anyway.
    ///   - present, decodes to 0: genuinely not duress-origin — falls through, same as above.
    ///   - present, fails to decode: cannot rule out that the real value was > 0 — exclude
    ///     outright, rather than falling through to a ceiling check that was never designed
    ///     to protect a duress-origin contact from the real depth-0 view. Falling through
    ///     here would be fail-open for exactly the contacts this field exists to protect.
    func isVisible(atDepth depth: Int) -> Bool {
        if let data = self.originDepth {
            guard let decrypted = data.decrypt(),
                  let origin = DepthCodec.decode(decrypted)
            else { return false }
            if origin > 0 { return depth >= origin }
        }
        guard let data = self.visibleThroughDepth else { return true }
        guard let decrypted = data.decrypt(),
              let value = DepthCodec.decode(decrypted)
        else { return false }   // non-nil field that won't decrypt = sensitive shell; exclude
        return value >= depth
    }

    /// Same as `isVisible(atDepth:)` but decrypts with an already-derived key instead of
    /// deriving one internally. For callers filtering many contacts in one pass — derive
    /// once, pass the same key to every call. Same three-state handling as above.
    func isVisible(atDepth depth: Int, usingKey key: SymmetricKey) -> Bool {
        if let data = self.originDepth {
            guard let decrypted = data.decrypt(using: key),
                  let origin = DepthCodec.decode(decrypted)
            else { return false }
            if origin > 0 { return depth >= origin }
        }
        guard let data = self.visibleThroughDepth else { return true }
        guard let decrypted = data.decrypt(using: key),
              let value = DepthCodec.decode(decrypted)
        else { return false }
        return value >= depth
    }

    /// Marked a global trustee at exactly `depth` — exact match, not a ceiling. Decrypts
    /// with an already-derived key; mirrors `ContactManager.isGlobalTrustee(_:)`.
    func isGlobalTrustee(atDepth depth: Int, usingKey key: SymmetricKey) -> Bool {
        guard let data      = self.globalTrusteeDepth,
              let decrypted = data.decrypt(using: key),
              let value     = DepthCodec.decode(decrypted)
        else { return false }
        return value == depth
    }
}

extension Contact.Profile {
    @Model
    final class PhoneNumber {
        var label: String = ""
        var value: String = "" // e.g., "+1 (555) 123-4567"
        
        init(label: String = "mobile", value: String = "") {
            self.label = label
            self.value = value
        }
        
        convenience init(from labeled: CNLabeledValue<CNPhoneNumber>) {
            let label = labeled.label ?? "other"
            let cleanedLabel = CNLabeledValue<CNPhoneNumber>.localizedString(forLabel: label)
            self.init(label: cleanedLabel, value: labeled.value.stringValue)
        }
        
        var profile: Contact.Profile?
    }

    @Model
    final class EmailAddress {
        var label: String = ""
        var value: String = ""
        
        init(label: String = "work", value: String = "") {
            self.label = label
            self.value = value
        }
        
        convenience init(from labeled: CNLabeledValue<NSString>) {
            let label = labeled.label ?? "other"
            let cleanedLabel = CNLabeledValue<NSString>.localizedString(forLabel: label)
            self.init(label: cleanedLabel, value: labeled.value as String)
        }
        
        var profile: Contact.Profile?
    }

    @Model
    final class PostalAddress {
        var label: String = ""
        
        var street: String = ""
        var city: String = ""
        var state: String = ""
        var postalCode: String = ""
        var country: String = ""
        var isoCountryCode: String = ""
        
        init(label: String = "home", street: String, city: String, state: String, postalCode: String, country: String, isoCountryCode: String) {
            self.label = label
        }
        
        convenience init(from labeled: CNLabeledValue<CNMutablePostalAddress>) {
            let label = labeled.label ?? "other"
            let address = labeled.value
            
            let street = [address.street, address.subLocality, address.subAdministrativeArea]
                .compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: ", ")
            let city = address.city
            let state = address.state
            let postalCode = address.postalCode
            let country = address.country
            let isoCountryCode = address.isoCountryCode
            
            self.init(label: label, street: street, city: city, state: state, postalCode: postalCode, country: country, isoCountryCode: isoCountryCode)
        }
        
        var profile: Contact.Profile?
    }

    @Model
    final class URLAddress {
        var label: String = ""
        var value: String = ""
        
        init(label: String = "homepage", value: String = "") {
            self.label = label
            self.value = value
        }
        
        convenience init(from labeled: CNLabeledValue<NSString>) {
            let label = labeled.label ?? "other"
            let cleanedLabel = CNLabeledValue<NSString>.localizedString(forLabel: label)
            
            self.init(label: cleanedLabel, value: labeled.value as String)
        }
        
        var profile: Contact.Profile?
    }
}

extension Contact.Profile {
    @Model
    class Key {
        var material: Data?
        var acquiredAt: Data?
        /// Encrypted hash of public key belonging to the user who acquired it through exchange.
        var owner: Data = Data()
        
        /// List of possible operations.
        var scopes: [Data]? {
            []
        }
        
        var expiredOn: Data?
        
        // MARK: - Hybrid PQ (SecureEnclave.MLKEM1024)
         
        /// Encrypted QuantumKeyMaterial blob.
        /// Contains both ML-KEM shared secrets and both ciphertexts from the exchange.
        /// Nil for contacts exchanged before the PQ upgrade (v1 classical exchange).
        /// Encrypted with the local DB key before storage — same as all other sensitive fields.
        var quantumKeyMaterialEncrypted: Data?

        init(material: Data? = nil, owner: Data, date: Data, quantumKeyMaterialEncrypted: Data? = nil) {
            self.material = material
            self.owner = owner
            self.acquiredAt = date
            self.quantumKeyMaterialEncrypted = quantumKeyMaterialEncrypted
        }
        
        init(material: Data? = nil, owner: Data, date: Data) {
            self.material = material
            self.owner = owner
            self.acquiredAt = date
        }
        
        var profile: Contact.Profile?
    }
}

extension Contact.Profile {
    /// Standard fetch descriptor for all UI list contexts.
    /// Excludes soft-deleted rows. Use this with @Query wherever a full contact list is needed.
    static var descriptor: FetchDescriptor<Contact.Profile> {
        FetchDescriptor(
            predicate: #Predicate { $0.deletionToken == nil },
            sortBy: [SortDescriptor(\.familyName)]
        )
    }
}

enum Scopes: Codable {
    /// Key can encrypt and decrypt.
    case crypto
    /// Key was acquired through `Nearby Interaction` and we have full confidence who it belongs to.
    case sign
    case none
}
