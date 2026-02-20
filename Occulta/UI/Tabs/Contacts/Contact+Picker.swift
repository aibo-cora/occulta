//
//  ContactPicker.swift
//  Occulta
//
//  Created by Yura on 1/10/26.
//

import UIKit
import SwiftUI
import Contacts
import ContactsUI

struct ContactPicker: UIViewControllerRepresentable {
    var onSelectIdentifiers: ([String]) -> Void   // return identifiers like ContactAccessButton
    
    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }
    
    func makeUIViewController(context: Context) -> CNContactPickerViewController {
        let picker = CNContactPickerViewController()
        picker.delegate = context.coordinator
        
        // Optional: show only phone numbers
        picker.displayedPropertyKeys = [CNContactPhoneNumbersKey]
        
        return picker
    }
    
    func updateUIViewController(_ uiViewController: CNContactPickerViewController, context: Context) {}
    
    class Coordinator: NSObject, CNContactPickerDelegate {
        let parent: ContactPicker
        
        init(_ parent: ContactPicker) {
            self.parent = parent
        }
        
        // Single contact selected (fallback)
        func contactPicker(_ picker: CNContactPickerViewController, didSelect contact: CNContact) {
            self.parent.onSelectIdentifiers([contact.identifier])
        }
        
        // Multiple contacts selected — this is the most similar to ContactAccessButton behavior
        func contactPicker(_ picker: CNContactPickerViewController, didSelect contacts: [CNContact]) {
            let identifiers = contacts.map { $0.identifier }
            
            self.parent.onSelectIdentifiers(identifiers)
        }
        
        // Optional: selected specific property (e.g. only phone)
        func contactPicker(_ picker: CNContactPickerViewController, didSelect contactProperty: CNContactProperty) {
            let identifier = contactProperty.contact.identifier
            
            parent.onSelectIdentifiers([identifier])
        }
    }
}
