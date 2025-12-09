//
//  Settings.swift
//  Maverick
//
//  Created by Yura on 12/9/25.
//

import SwiftUI

struct Settings: View {
    @State private var porter = Manager.Porter()
    
    @Environment(ContactManager.self) private var contactManager: ContactManager
    
    var body: some View {
        List {
            Section {
                Button {
                    
                    self.porter.export(data: <#T##Data#>)
                } label: {
                    Text("Export Contacts")
                }
            } header: {
                Text("Recovery")
            } footer: {
                Text("Import and Export your contacts securely to a new device.")
            }
        }
    }
}

#Preview {
    Settings()
        .environment(ContactManager.preview)
}
