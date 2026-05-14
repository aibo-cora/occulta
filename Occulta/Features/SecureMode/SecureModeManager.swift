//
//  SecureModeManager.swift
//  Occulta
//

import SwiftData
import Observation

@Observable
final class SecureModeManager {

    // MARK: - State

    enum State {
        case inactive
        case active
        case duress
    }

    private(set) var state: State

    var isActive:      Bool { self.state != .inactive }
    var isDuressActive: Bool { self.state == .duress }

    // MARK: - Init

    init(modelContainer: ModelContainer) {
        let context = ModelContext(modelContainer)
        let configs = try? context.fetch(FetchDescriptor<SecureModeConfig>())
        self.state = (configs?.first?.isActivated == true) ? .active : .inactive
    }

    // MARK: - Transitions

    func activate()    { self.state = .active   }
    func enterDuress() { self.state = .duress   }
    func deactivate()  { self.state = .inactive }
}
