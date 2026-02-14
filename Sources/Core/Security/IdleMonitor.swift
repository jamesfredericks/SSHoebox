import Foundation
import Combine
import AppKit

/// Monitors user activity and publishes events when the app has been idle for too long
@MainActor
public class IdleMonitor: ObservableObject {
    @Published public var isIdle: Bool = false
    
    private var lastActivityTime: Date = Date()
    private var timer: Timer?
    private var eventMonitor: Any?
    public var timeoutInterval: TimeInterval
    
    public init(timeoutInterval: TimeInterval) {
        self.timeoutInterval = timeoutInterval
    }
    
    /// Start monitoring user activity
    public func startMonitoring() {
        lastActivityTime = Date()
        
        // Monitor global events (mouse and keyboard)
        eventMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.mouseMoved, .leftMouseDown, .rightMouseDown, .keyDown]) { [weak self] _ in
            Task { @MainActor in
                self?.resetActivity()
            }
        }
        
        // Also monitor local events (within the app)
        NSEvent.addLocalMonitorForEvents(matching: [.mouseMoved, .leftMouseDown, .rightMouseDown, .keyDown]) { [weak self] event in
            Task { @MainActor in
                self?.resetActivity()
            }
            return event
        }
        
        // Check idle status every 30 seconds
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.checkIdleStatus()
            }
        }
    }
    
    /// Stop monitoring
    public func stopMonitoring() {
        if let monitor = eventMonitor {
            NSEvent.removeMonitor(monitor)
            eventMonitor = nil
        }
        timer?.invalidate()
        timer = nil
        isIdle = false
    }
    
    /// Reset activity timer (user did something)
    private func resetActivity() {
        lastActivityTime = Date()
        if isIdle {
            isIdle = false
        }
    }
    
    /// Check if we've been idle too long
    private func checkIdleStatus() {
        // Never timeout if interval is 0 (disabled)
        guard timeoutInterval > 0 else { return }
        
        let idleTime = Date().timeIntervalSince(lastActivityTime)
        if idleTime >= timeoutInterval && !isIdle {
            isIdle = true
        }
    }
}
