import SwiftUI
import SSHoeboxCore

struct GeneratorView: View {
    @ObservedObject private var themeManager = ThemeManager.shared
    @StateObject private var viewModel = GeneratorViewModel()
    @State private var copied = false
    
    var body: some View {
        VStack(spacing: 20) {
            // Display Area
            ZStack {
                RoundedRectangle(cornerRadius: 12)
                    .fill(DesignSystem.Colors.surface)
                    .frame(height: 100)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(DesignSystem.Colors.border, lineWidth: 1)
                    )
                
                Text(viewModel.generatedPassword)
                    .font(.system(.title, design: .monospaced))
                    .foregroundStyle(DesignSystem.Colors.textPrimary)
                    .textSelection(.enabled)
                    .multilineTextAlignment(.center)
                    .padding()
            }
            .padding(.horizontal)
            
            // Actions
            HStack {
                Button(action: {
                    viewModel.generate()
                    copied = false
                }) {
                    Label("Regenerate", systemImage: "arrow.clockwise")
                }
                
                Button(action: {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(viewModel.generatedPassword, forType: .string)
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                        copied = false
                    }
                }) {
                    Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                }
            }
            .tint(DesignSystem.Colors.accent)
            
            Divider()
                .background(DesignSystem.Colors.border)
            
            // Options
            Form {
                Section {
                    HStack {
                        Text("Type")
                            .foregroundStyle(DesignSystem.Colors.textPrimary)
                        Spacer()
                        Picker("", selection: $viewModel.options.type) {
                            ForEach(GeneratorType.allCases) { type in
                                Text(type.rawValue).tag(type)
                            }
                        }
                        .pickerStyle(.segmented)
                        .frame(width: 200)
                    }
                    .onChange(of: viewModel.options.type) { _ in viewModel.generate() }
                } header: {
                    Text("Generator Settings")
                        .foregroundStyle(DesignSystem.Colors.textSecondary)
                }
                
                if viewModel.options.type == .password {
                    Section {
                        Slider(value: Binding(
                            get: { Double(viewModel.options.length) },
                            set: { viewModel.options.length = Int($0) }
                        ), in: 6...128, step: 1)
                    } header: {
                        Text("Length: \(Int(viewModel.options.length))")
                            .foregroundStyle(DesignSystem.Colors.textPrimary)
                    }
                    .onChange(of: viewModel.options.length) { _ in viewModel.generate() }
                    
                    Section {
                        Group {
                            Toggle("A-Z", isOn: $viewModel.options.useUppercase)
                            Toggle("a-z", isOn: $viewModel.options.useLowercase)
                            Toggle("0-9", isOn: $viewModel.options.useDigits)
                            Toggle("!@#", isOn: $viewModel.options.useSymbols)
                            Toggle("Avoid Ambiguous", isOn: $viewModel.options.avoidAmbiguous)
                        }
                        .foregroundStyle(DesignSystem.Colors.textPrimary)
                    } header: {
                        Text("Character Sets")
                            .foregroundStyle(DesignSystem.Colors.textSecondary)
                    }
                    .onChange(of: viewModel.options.useUppercase) { _ in viewModel.generate() }
                    .onChange(of: viewModel.options.useLowercase) { _ in viewModel.generate() }
                    .onChange(of: viewModel.options.useDigits) { _ in viewModel.generate() }
                    .onChange(of: viewModel.options.useSymbols) { _ in viewModel.generate() }
                    .onChange(of: viewModel.options.avoidAmbiguous) { _ in viewModel.generate() }
                    
                } else {
                    Section {
                        Slider(value: Binding(
                            get: { Double(viewModel.options.passphraseWords) },
                            set: { viewModel.options.passphraseWords = Int($0) }
                        ), in: 3...12, step: 1)
                    } header: {
                        Text("Words: \(viewModel.options.passphraseWords)")
                            .foregroundStyle(DesignSystem.Colors.textPrimary)
                    }
                    .onChange(of: viewModel.options.passphraseWords) { _ in viewModel.generate() }
                    
                    Section {
                        HStack {
                            Text("Separator")
                                .foregroundStyle(DesignSystem.Colors.textPrimary)
                            Spacer()
                            Picker("", selection: $viewModel.options.separator) {
                                Text("Hyphen (-)").tag("-")
                                Text("Underscore (_)").tag("_")
                                Text("Space ( )").tag(" ")
                                Text("Period (.)").tag(".")
                            }
                            .frame(width: 200)
                        }
                    } header: {
                        Text("Formatting")
                            .foregroundStyle(DesignSystem.Colors.textSecondary)
                    }
                    .onChange(of: viewModel.options.separator) { _ in viewModel.generate() }
                }
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden) // Ensure black background shows through
            .tint(DesignSystem.Colors.accent)
        }
        .padding(.vertical)
        .background(DesignSystem.Colors.background)
        .navigationTitle("Password Generator")
    }
}
