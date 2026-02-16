import SwiftUI

struct PreferencesView: View {
    @ObservedObject var themeManager = ThemeManager.shared
    @State private var autoLockTimeout: Int = 15
    
    var body: some View {
        Form {
            Section {
                Picker("Auto-lock after", selection: $autoLockTimeout) {
                    Text("5 minutes").tag(5)
                        .foregroundColor(DesignSystem.Colors.textPrimary)
                    Text("15 minutes").tag(15)
                        .foregroundColor(DesignSystem.Colors.textPrimary)
                    Text("30 minutes").tag(30)
                        .foregroundColor(DesignSystem.Colors.textPrimary)
                    Text("1 hour").tag(60)
                        .foregroundColor(DesignSystem.Colors.textPrimary)
                    Text("Never").tag(0)
                        .foregroundColor(DesignSystem.Colors.textPrimary)
                }
                .onChange(of: autoLockTimeout) { newValue in
                    UserDefaults.standard.set(newValue, forKey: "autoLockTimeout")
                    UserDefaults.standard.set(true, forKey: "hasSetAutoLockTimeout")
                }
            } header: {
                Text("Security")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            } footer: {
                Text("Automatically lock the vault after a period of inactivity.")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }
            
            Section {
                Picker(selection: Binding(
                    get: { themeManager.currentTheme.id },
                    set: { themeManager.setTheme(id: $0) }
                )) {
                    ForEach(AppTheme.allThemes) { theme in
                        Text(theme.name)
                            .tag(theme.id)
                            .foregroundStyle(DesignSystem.Colors.textPrimary)
                    }
                } label: {
                    Text("Theme")
                        .foregroundStyle(DesignSystem.Colors.textPrimary)
                }
                .pickerStyle(.inline)
                .labelsHidden()
            } header: {
                Text("Appearance")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }
            
            Section {
                HStack {
                    Text("Version")
                        .foregroundStyle(DesignSystem.Colors.textPrimary)
                    Spacer()
                    Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0")
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                }
            } header: {
                Text("About")
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
            }
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
        .background(DesignSystem.Colors.background)
        .preferredColorScheme(themeManager.currentTheme.colorScheme)
        .tint(DesignSystem.Colors.accent)
        .navigationTitle("Preferences")
        .onAppear {
            // Load saved preference
            let saved = UserDefaults.standard.integer(forKey: "autoLockTimeout")
            if saved == 0 && !UserDefaults.standard.bool(forKey: "hasSetAutoLockTimeout") {
                autoLockTimeout = 15 // Default
            } else {
                autoLockTimeout = saved
            }
        }
    }
}
