import AppIntents

struct BatonPassShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: SendClipboardIntent(),
            phrases: ["Send to \(.applicationName)"],
            shortTitle: "Send to BatonPass",
            systemImageName: "paperplane"
        )
    }
}
