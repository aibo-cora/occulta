//
//  QRCode+Generator.swift
//  Occulta
//
//  Created by Yura on 10/13/25.
//

#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif
import Foundation
import CoreImage.CIFilterBuiltins

extension QRCode {
    @Observable
    class Generator {
        private let context: CIContext
        
        init() {
            self.context = CIContext()
        }
        
#if os(iOS)
        func generate(from string: String) -> UIImage {
            let generator = CIFilter.qrCodeGenerator()
            
            generator.message = string.data(using: .utf8) ?? Data()
            
            if let image = generator.outputImage, let cgImage = self.context.createCGImage(image, from: image.extent) {
                return UIImage(cgImage: cgImage)
            }
            
            return UIImage(systemName: "qrcode") ?? UIImage()
        }
#elseif os(macOS)
        func generate(from string: String) -> NSImage {
            let generator = CIFilter.qrCodeGenerator()
            
            generator.message = string.data(using: .utf8) ?? Data()
            
            if let image = generator.outputImage, let cgImage = self.context.createCGImage(image, from: image.extent) {
                return UIImage(cgImage: cgImage)
            }
            
            return NSImage(systemName: "qrcode") ?? NSImage()
        }
#endif
    }
}

