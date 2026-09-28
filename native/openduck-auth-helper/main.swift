import AppKit
import Foundation
import LocalAuthentication

// OpenDuck owner-auth helper. This unsigned/ad-hoc development binary has no
// network, shell, WebView, or reusable proof capability. It renders the exact
// bounded dossier supplied by the Controller before accepting a challenge.
let maxLine = 64 * 1024
let maxText = 8 * 1024
let maxField = 2 * 1024

struct Message: Codable {
    let type: String
    let session_id: String?
    let display_instance_id: String?
    let action_type: String?
    let title: String?
    let text: String?
    let destination: String?
    let risk: String?
    let expires_at: String?
    let preview_digest: String?
    let destination_digest: String?
    let challenge: String?
}

struct Decision: Codable {
    let type: String
    let result: Result
}
struct Result: Codable {
    let decision: String
    let challenge: String
    let session_id: String
    let display_instance_id: String
    let timestamp: String
}

final class Helper: NSObject, NSApplicationDelegate {
    private var window: NSWindow?
    private var session = ""
    private var display = ""
    private var actionType = ""
    private var title = ""
    private var preview = ""
    private var destination = ""
    private var risk = ""
    private var expiry = ""
    private var previewDigest = ""
    private var destinationDigest = ""
    private var displayNonce = ""
    private var didRender = false
    private var outputLock = NSLock()

    func applicationDidFinishLaunching(_ notification: Notification) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in self?.readLoop() }
    }

    private func emit<T: Encodable>(_ value: T) {
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(value), data.count <= maxLine else { return }
        outputLock.lock(); defer { outputLock.unlock() }
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([0x0a]))
    }

    private func readLoop() {
        while let data = readLineBounded(), let msg = try? JSONDecoder().decode(Message.self, from: data) {
            if msg.type == "preview",
               let sid = msg.session_id, let did = msg.display_instance_id,
               let action = msg.action_type, let heading = msg.title, let text = msg.text,
               let dest = msg.destination, let riskValue = msg.risk, let expires = msg.expires_at,
               let pd = msg.preview_digest, let dd = msg.destination_digest,
               !sid.isEmpty, !did.isEmpty, !action.isEmpty, !heading.isEmpty, !text.isEmpty,
               !dest.isEmpty, !riskValue.isEmpty, !expires.isEmpty, isDigest(pd), isDigest(dd),
               text.utf8.count <= maxText, action.utf8.count <= maxField, heading.utf8.count <= maxField,
               dest.utf8.count <= maxField, riskValue.utf8.count <= maxField, expires.utf8.count <= maxField,
               !didRender {
                session = sid; display = did; actionType = action; title = heading; preview = text
                destination = dest; risk = riskValue; expiry = expires; previewDigest = pd; destinationDigest = dd
                DispatchQueue.main.async { [weak self] in self?.showPreview() }
            } else if msg.type == "challenge", let sid = msg.session_id, let challenge = msg.challenge,
                      sid == session, didRender, !challenge.isEmpty {
                DispatchQueue.main.async { [weak self] in self?.showApproval(challenge: challenge) }
            } else { exit(2) }
        }
        exit(2)
    }

    private func isDigest(_ value: String) -> Bool {
        let hex = value.hasPrefix("sha256:") ? String(value.dropFirst(7)) : value
        guard hex.utf8.count == 64 else { return false }
        return hex.unicodeScalars.allSatisfy { ($0.value >= 48 && $0.value <= 57) || ($0.value >= 65 && $0.value <= 70) || ($0.value >= 97 && $0.value <= 102) }
    }

    private func readLineBounded() -> Data? {
        var data = Data()
        while data.count <= maxLine {
            let chunk = FileHandle.standardInput.readData(ofLength: 1)
            if chunk.isEmpty { return nil }
            data.append(chunk)
            if let newline = data.firstIndex(of: 0x0a) { return Data(data[..<newline]) }
        }
        return nil
    }

    private func label(_ text: String, bold: Bool = false) -> NSTextField {
        let value = NSTextField(wrappingLabelWithString: text)
        value.font = bold ? NSFont.boldSystemFont(ofSize: 15) : NSFont.systemFont(ofSize: 13)
        value.lineBreakMode = .byWordWrapping
        return value
    }

    private func showPreview() {
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 720, height: 620), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        w.title = "OpenDuck Controller — synthetic preview"
        let content = NSView(frame: w.contentRect(forFrameRect: w.frame))
        let heading = label(title, bold: true); heading.frame = NSRect(x: 24, y: 560, width: 672, height: 30)
        let meta = label("Действие: \(actionType)\nНазначение: \(destination)\nРиск: \(risk)\nИстекает: \(expiry)"); meta.frame = NSRect(x: 24, y: 440, width: 672, height: 110)
        let digest = label("Preview digest: \(previewDigest)\nDestination digest: \(destinationDigest)"); digest.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular); digest.frame = NSRect(x: 24, y: 370, width: 672, height: 60)
        let text = NSTextView(frame: NSRect(x: 0, y: 0, width: 672, height: 300)); text.string = preview; text.isEditable = false; text.isSelectable = true; text.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular); text.textContainer?.widthTracksTextView = true
        let scroll = NSScrollView(frame: NSRect(x: 24, y: 48, width: 672, height: 300)); scroll.hasVerticalScroller = true; scroll.hasHorizontalScroller = false; scroll.documentView = text; scroll.borderType = .bezelBorder
        content.addSubview(heading); content.addSubview(meta); content.addSubview(digest); content.addSubview(scroll); w.contentView = content
        w.center(); w.makeKeyAndOrderFront(nil); w.orderFrontRegardless(); w.displayIfNeeded(); window = w
        displayNonce = UUID().uuidString
        DispatchQueue.main.async { [weak self, weak w] in
            guard let self = self, let w = w else { return }
            w.orderFrontRegardless(); w.displayIfNeeded(); self.didRender = true
            self.emit(["type": "rendered", "session_id": self.session, "display_instance_id": self.display, "display_nonce": self.displayNonce, "preview_digest": self.previewDigest, "destination_digest": self.destinationDigest])
        }
    }

    private func showApproval(challenge: String) {
        guard let w = window else { emitDecision("reject", challenge: challenge); return }
        let alert = NSAlert(); alert.messageText = "Подтвердить действие OpenDuck?"
        alert.informativeText = "\(title)\n\nДействие: \(actionType)\nНазначение: \(destination)\nРиск: \(risk)\nИстекает: \(expiry)\n\nPreview digest: \(previewDigest)\nDestination digest: \(destinationDigest)"
        alert.addButton(withTitle: "Разрешить"); alert.addButton(withTitle: "Отклонить")
        alert.beginSheetModal(for: w) { [weak self] response in
            guard let self = self else { return }
            let decision = response == .alertFirstButtonReturn ? "approve" : "reject"
            let context = LAContext(); var error: NSError?
            guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error), context.biometryType == .touchID else { self.emitDecision("reject", challenge: challenge); return }
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: decision == "approve" ? "Подтвердите действие OpenDuck" : "Подтвердите отклонение действия OpenDuck") { [weak self] ok, _ in
                DispatchQueue.main.async { self?.emitDecision(ok ? decision : "reject", challenge: challenge) }
            }
        }
    }

    private func emitDecision(_ decision: String, challenge: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        emit(Decision(type: "decision", result: Result(decision: decision, challenge: challenge, session_id: session, display_instance_id: display, timestamp: timestamp)))
        NSApp.terminate(nil)
    }
}

let app = NSApplication.shared
let delegate = Helper(); app.delegate = delegate; app.setActivationPolicy(.accessory); app.run()
