//
//  GroupRevokedNoticeV3.swift
//  Occulta
//
//  What the group screens say when members have a revoked key: they stay in the group, and a message to it leaves
//  them out until keys are exchanged again. Always visible, never dismissible, like every `CardNotice`.
//  `Docs/Bugs/v2.1.0/Revoked-Contact-Stays-In-Group-With-No-Warning-And-Group-Send-Fails-Opaquely.md`.
//

import SwiftUI

struct GroupRevokedNoticeV3: View {
    /// The members at the current depth with no current key.
    let names: [String]
    /// Every member at the current depth can't receive.
    let everyoneRevoked: Bool

    var body: some View {
        CardNotice(tone: .warn, label: "Key revoked", text: Self.text(names: self.names, everyoneRevoked: self.everyoneRevoked))
    }

    static func text(names: [String], everyoneRevoked: Bool) -> String {
        if everyoneRevoked {
            return "No one in this group can receive messages: every member's key is revoked. Exchange keys again to send to them."
        }
        let who: String
        switch names.count {
        case 1:  who = "\(names[0])'s key is revoked."
        case 2:  who = "\(names[0]) and \(names[1]) have revoked keys."
        default: who = "\(names[0]), \(names[1]) and \(names.count - 2) other\(names.count == 3 ? "" : "s") have revoked keys."
        }
        return "\(who) A message to this group leaves them out until you exchange keys again."
    }
}
