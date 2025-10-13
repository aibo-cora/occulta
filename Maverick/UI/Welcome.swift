//
//  Welcome.swift
//  Maverick
//
//  Created by Yura on 10/13/25.
//

import SwiftUI

struct Welcome: View {
    @State private var generator = QRCode.Generator()
    @State private var code: QRCode? = QRCode(id: UUID().uuidString, key: "")
    
    var body: some View {
        Text(/*@START_MENU_TOKEN@*/"Hello, World!"/*@END_MENU_TOKEN@*/)
            .sheet(item: self.$code) { code in
                let qrCode = self.generator.generate(from: code.id)
                
                Image(uiImage: qrCode)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
            }
    }
}

#Preview {
    Welcome()
}
