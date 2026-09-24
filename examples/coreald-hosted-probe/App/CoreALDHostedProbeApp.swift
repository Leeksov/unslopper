import BackgroundAssets
import SwiftUI

@main
struct CoreALDHostedProbeApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}

struct ContentView: View {
    private let packID = "CoreALDTest"
    @State private var message = "Ready"
    @State private var busy = false

    var body: some View {
        VStack(spacing: 16) {
            Text("CoreALD Hosted Probe").font(.title2)
            Text(message).textSelection(.enabled)
            Button("Download test pack") {
                Task { await download() }
            }.disabled(busy)
            Button("Remove and redownload") {
                Task { await redownload() }
            }.disabled(busy)
        }
        .padding()
    }

    @MainActor
    private func download() async {
        busy = true
        defer { busy = false }
        do {
            let manager = AssetPackManager.shared
            message = "Finding \(packID)…"
            let pack = try await manager.assetPack(withID: packID)
            message = "Downloading \(pack.id)…"
            try await manager.ensureLocalAvailability(of: pack)
            message = "Downloaded \(pack.id), version \(pack.version)"
        } catch {
            message = "Download failed: \(error.localizedDescription)"
        }
    }

    @MainActor
    private func redownload() async {
        busy = true
        defer { busy = false }
        do {
            let manager = AssetPackManager.shared
            message = "Removing cached \(packID)…"
            try await manager.remove(assetPackWithID: packID)
            message = "Finding \(packID)…"
            let pack = try await manager.assetPack(withID: packID)
            message = "Redownloading \(pack.id)…"
            try await manager.ensureLocalAvailability(of: pack)
            message = "Redownloaded \(pack.id), version \(pack.version)"
        } catch {
            message = "Redownload failed: \(error.localizedDescription)"
        }
    }
}
