//
//  UpdatesManager.swift
//  Ice
//

import SwiftUI

/// App updates are disabled for this fork.
@MainActor
final class UpdatesManager: NSObject, ObservableObject {
    /// Retains the app-state interface without starting a Sparkle updater.
    init(appState: AppState) {
        super.init()
    }

    func performSetup() { }

    /// Intentionally ignores update requests, including notification actions.
    @objc func checkForUpdates() { }
}
