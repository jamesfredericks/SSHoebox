import SwiftUI

struct EmptyStateView: View {
    let title: String
    let description: String
    let systemImage: String
    
    var body: some View {
        VStack(spacing: DesignSystem.Spacing.medium) {
            Image(systemName: systemImage)
                .font(.system(size: 48))
                .foregroundStyle(DesignSystem.Colors.textSecondary.opacity(0.5))
            
            VStack(spacing: DesignSystem.Spacing.tight) {
                Text(title)
                    .font(DesignSystem.Typography.heading())
                    .foregroundStyle(DesignSystem.Colors.textPrimary)
                
                Text(description)
                    .font(DesignSystem.Typography.body())
                    .foregroundStyle(DesignSystem.Colors.textSecondary)
                    .multilineTextAlignment(.center)
            }
        }
        .padding(DesignSystem.Spacing.extraLarge)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(DesignSystem.Colors.surface.opacity(0.5))
        .cornerRadius(DesignSystem.Radius.lg)
    }
}
