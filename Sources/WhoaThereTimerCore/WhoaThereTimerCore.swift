import AppKit
import Combine
import Darwin
import SwiftUI

enum TimerRunState: String, Codable {
    case idle
    case running
    case paused
}

enum PomodoroMode: String, CaseIterable, Codable, Identifiable {
    case off
    case focus25
    case focus50

    var id: String { rawValue }

    var title: String {
        switch self {
        case .focus25: "25"
        case .focus50: "50"
        case .off: "Off"
        }
    }

    var minutes: Int? {
        switch self {
        case .focus25: 25
        case .focus50: 50
        case .off: nil
        }
    }
}

struct TimeEntry: Identifiable, Codable, Equatable {
    let id: UUID
    let start: Date
    let end: Date
    let note: String
    let duration: TimeInterval

    init(id: UUID = UUID(), start: Date, end: Date, note: String, duration: TimeInterval) {
        self.id = id
        self.start = start
        self.end = end
        self.note = note
        self.duration = duration
    }
}

final class TimerModel: ObservableObject {
    let objectWillChange = ObservableObjectPublisher()

    private enum Keys {
        static let entries = "whoathere.entries"
        static let note = "whoathere.current-note"
        static let pomodoroMode = "whoathere.pomodoro-mode"
    }

    var onChange: (() -> Void)?
    var state: TimerRunState = .idle
    var pomodoroMode: PomodoroMode = .off
    var note: String = ""
    var entries: [TimeEntry] = []

    private var intervalStartedAt: Date?
    private var runningStartedAt: Date?
    private var activeEndedAt: Date?
    private var accumulated: TimeInterval = 0
    private var pomodoroAlerted = false

    init(loadPersistedState: Bool = true) {
        if loadPersistedState {
            load()
        }
    }

    static func preview(state: TimerRunState = .running, elapsed: TimeInterval = 32 * 60 + 14) -> TimerModel {
        let model = TimerModel(loadPersistedState: false)
        let now = Date()
        let calendar = Calendar.current
        let today = calendar.startOfDay(for: now)

        model.state = state
        model.pomodoroMode = state == .idle ? .off : .focus25
        model.note = state == .idle ? "" : "Menu bar timer polish"
        model.intervalStartedAt = now.addingTimeInterval(-elapsed)
        model.activeEndedAt = now

        switch state {
        case .running:
            model.runningStartedAt = now.addingTimeInterval(-elapsed)
            model.accumulated = 0
        case .paused:
            model.runningStartedAt = nil
            model.accumulated = elapsed
        case .idle:
            model.intervalStartedAt = nil
            model.runningStartedAt = nil
            model.accumulated = 0
        }

        model.entries = [
            TimeEntry(
                start: today.addingTimeInterval(10 * 3600 + 2 * 60),
                end: today.addingTimeInterval(10 * 3600 + 34 * 60),
                note: "Menu bar timer polish",
                duration: 32 * 60
            ),
            TimeEntry(
                start: today.addingTimeInterval(9 * 3600 + 10 * 60),
                end: today.addingTimeInterval(9 * 3600 + 52 * 60),
                note: "Invoice cleanup",
                duration: 42 * 60
            ),
            TimeEntry(
                start: today.addingTimeInterval(8 * 3600 + 15 * 60),
                end: today.addingTimeInterval(8 * 3600 + 55 * 60),
                note: "Client planning notes",
                duration: 40 * 60
            ),
            TimeEntry(
                start: today.addingTimeInterval(-24 * 3600 + 13 * 3600),
                end: today.addingTimeInterval(-24 * 3600 + 15 * 3600 + 35 * 60),
                note: "API cleanup and notes",
                duration: 2 * 3600 + 35 * 60
            ),
            TimeEntry(
                start: today.addingTimeInterval(-2 * 24 * 3600 + 10 * 3600),
                end: today.addingTimeInterval(-2 * 24 * 3600 + 11 * 3600 + 45 * 60),
                note: "Client implementation work",
                duration: 1 * 3600 + 45 * 60
            )
        ]

        return model
    }

    var elapsed: TimeInterval {
        elapsed(at: Date())
    }

    var statusTitle: String {
        switch state {
        case .running:
            return "● \(Self.clock(elapsed))"
        case .paused:
            return "Ⅱ \(Self.clock(elapsed))"
        case .idle:
            return "TC"
        }
    }

    var stateLabel: String {
        switch state {
        case .idle: "Ready"
        case .running: "Running"
        case .paused: "Paused"
        }
    }

    var isActive: Bool {
        state == .running || state == .paused
    }

    var pomodoroSummary: String {
        guard let minutes = pomodoroMode.minutes else {
            return "Focus off"
        }

        guard isActive else {
            return "\(minutes)m focus"
        }

        let target = TimeInterval(minutes * 60)
        let remaining = target - elapsed
        if remaining >= 0 {
            return "Focus \(Self.clock(remaining)) left"
        }
        return "Focus complete"
    }

    var todayEntries: [TimeEntry] {
        let calendar = Calendar.current
        return entries.filter { calendar.isDateInToday($0.start) }
    }

    var todayHours: Double {
        todayEntries.reduce(0) { $0 + $1.duration / 3600 }
    }

    var weekHours: Double {
        let calendar = Calendar.current
        let now = Date()
        return entries
            .filter { entry in
                calendar.isDate(entry.start, equalTo: now, toGranularity: .weekOfYear)
                    && calendar.isDate(entry.start, equalTo: now, toGranularity: .yearForWeekOfYear)
            }
            .reduce(0) { $0 + $1.duration / 3600 }
    }

    var recentEntries: [TimeEntry] {
        Array(entries.prefix(3))
    }

    var recentEntriesHours: Double {
        recentEntries.reduce(0) { $0 + $1.duration / 3600 }
    }

    var remainingWeekHours: Double {
        max(0, 20 - weekHours)
    }

    func tick() {
        guard state == .running else {
            return
        }
        firePomodoroAlertIfNeeded()
        objectWillChange.send()
        onChange?()
    }

    func startOrResume() {
        let now = Date()

        switch state {
        case .idle:
            intervalStartedAt = now
            runningStartedAt = now
            activeEndedAt = now
            accumulated = 0
            pomodoroAlerted = false
            state = .running
        case .paused:
            runningStartedAt = now
            state = .running
        case .running:
            pause()
            return
        }

        changed()
    }

    func pause() {
        guard state == .running, let runningStartedAt else {
            return
        }

        let now = Date()
        accumulated += now.timeIntervalSince(runningStartedAt)
        self.runningStartedAt = nil
        activeEndedAt = now
        state = .paused
        changed()
    }

    func stopAndSave() {
        let now = Date()
        let duration = elapsed(at: now)
        guard duration >= 1, let start = intervalStartedAt else {
            resetInterval()
            changed()
            return
        }

        let end = state == .paused ? (activeEndedAt ?? now) : now
        let cleanNote = note.trimmingCharacters(in: .whitespacesAndNewlines)
        let entry = TimeEntry(
            start: start,
            end: end,
            note: cleanNote.isEmpty ? "Consulting work" : cleanNote,
            duration: duration
        )

        entries.insert(entry, at: 0)
        resetInterval()
        saveEntries()
        changed()
    }

    func discardCurrentInterval() {
        resetInterval()
        changed()
    }

    func setNote(_ value: String) {
        note = value
        UserDefaults.standard.set(value, forKey: Keys.note)
        objectWillChange.send()
        onChange?()
    }

    func setPomodoroMode(_ value: PomodoroMode) {
        pomodoroMode = value
        pomodoroAlerted = false
        UserDefaults.standard.set(value.rawValue, forKey: Keys.pomodoroMode)
        changed()
    }

    private func firePomodoroAlertIfNeeded() {
        guard !pomodoroAlerted,
              let minutes = pomodoroMode.minutes,
              elapsed >= TimeInterval(minutes * 60) else {
            return
        }

        pomodoroAlerted = true
        NSSound.beep()
    }

    private func elapsed(at date: Date) -> TimeInterval {
        guard state == .running, let runningStartedAt else {
            return accumulated
        }
        return accumulated + date.timeIntervalSince(runningStartedAt)
    }

    private func resetInterval() {
        state = .idle
        intervalStartedAt = nil
        runningStartedAt = nil
        activeEndedAt = nil
        accumulated = 0
        pomodoroAlerted = false
    }

    private func changed() {
        objectWillChange.send()
        onChange?()
    }

    private func load() {
        note = UserDefaults.standard.string(forKey: Keys.note) ?? ""

        if let rawMode = UserDefaults.standard.string(forKey: Keys.pomodoroMode),
           let mode = PomodoroMode(rawValue: rawMode) {
            pomodoroMode = mode
        }

        guard let data = UserDefaults.standard.data(forKey: Keys.entries) else {
            return
        }

        if let decoded = try? JSONDecoder().decode([TimeEntry].self, from: data) {
            entries = decoded
        }
    }

    private func saveEntries() {
        guard let data = try? JSONEncoder().encode(entries) else {
            return
        }
        UserDefaults.standard.set(data, forKey: Keys.entries)
    }

    static func clock(_ interval: TimeInterval) -> String {
        let total = max(0, Int(interval.rounded(.down)))
        let hours = total / 3600
        let minutes = (total % 3600) / 60
        let seconds = total % 60

        if hours > 0 {
            return "\(hours):\(String(format: "%02d", minutes)):\(String(format: "%02d", seconds))"
        }

        return "\(minutes):\(String(format: "%02d", seconds))"
    }

    static func invoiceHours(_ interval: TimeInterval) -> String {
        let roundedQuarter = (interval / 3600 * 4).rounded() / 4
        if roundedQuarter == 0 {
            return "\(max(1, Int(interval / 60)))m"
        }

        if roundedQuarter.rounded(.down) == roundedQuarter {
            return "\(Int(roundedQuarter))h"
        }

        return String(format: "%.2gh", roundedQuarter)
    }
}

struct TimerPopoverView: View {
    @ObservedObject var model: TimerModel
    @State private var showsDetails = false

    init(model: TimerModel, showsDetails: Bool = false) {
        self.model = model
        _showsDetails = State(initialValue: showsDetails)
    }

    var body: some View {
        VStack(spacing: 0) {
            timerSection
            separator
            summarySection

            if showsDetails {
                separator
                detailsSection
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .frame(width: 300)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var timerSection: some View {
        VStack(spacing: 8) {
            noteField

            HStack(spacing: 7) {
                Button {
                    if model.state == .running {
                        model.pause()
                    } else {
                        model.startOrResume()
                    }
                } label: {
                    TimerActionLabel(
                        title: model.state == .running ? "Pause" : "Start",
                        systemImage: model.state == .running ? "pause.fill" : "play.fill",
                        accent: model.state == .running ? .primary : .accentColor,
                        filled: model.state != .running
                    )
                }
                .buttonStyle(.plain)

                if model.isActive {
                    Button {
                        model.stopAndSave()
                    } label: {
                        TimerActionLabel(
                            title: "Log",
                            systemImage: "checkmark",
                            accent: .accentColor,
                            filled: true
                        )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .padding(.bottom, 10)
    }

    @ViewBuilder
    private var noteField: some View {
        if CommandLine.arguments.contains("--render-screenshot") {
            Text(model.note.isEmpty ? "What are you working on?" : model.note)
                .font(.system(size: 13))
                .foregroundStyle(model.note.isEmpty ? .tertiary : .primary)
                .lineLimit(1)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 8)
                .padding(.vertical, 6)
                .background(
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .fill(Color(nsColor: .controlBackgroundColor))
                )
        } else {
            TextField("What are you working on?", text: Binding(
                get: { model.note },
                set: { model.setNote($0) }
            ))
            .textFieldStyle(.plain)
            .font(.system(size: 13))
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(Color(nsColor: .controlBackgroundColor))
            )
        }
    }

    private var summarySection: some View {
        VStack(spacing: 7) {
            HStack {
                Text("Today \(compactHours(model.todayHours))")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.primary)

                Spacer()

                Text("Week \(compactHours(model.weekHours)) / 20h")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.primary)
            }

            GeometryReader { proxy in
                ZStack(alignment: .leading) {
                    Capsule()
                        .fill(Color(nsColor: .separatorColor).opacity(0.28))

                    Capsule()
                        .fill(Color.accentColor)
                        .frame(width: proxy.size.width * min(1, model.weekHours / 20))
                }
            }
            .frame(height: 5)

            Button {
                showsDetails.toggle()
            } label: {
                HStack(spacing: 4) {
                    Image(systemName: showsDetails ? "chevron.up" : "chevron.down")
                        .font(.system(size: 9, weight: .semibold))
                    Text(showsDetails ? "Hide Details" : "Details")
                        .font(.system(size: 11, weight: .medium))
                }
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
        .padding(.top, 9)
    }

    private var detailsSection: some View {
        VStack(spacing: 8) {
            if model.pomodoroMode != .off {
                focusSection
            }

            recentEntriesSection

            if model.isActive {
                Button {
                    model.discardCurrentInterval()
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: "trash")
                            .font(.system(size: 10, weight: .semibold))
                        Text("Discard")
                            .font(.system(size: 11, weight: .medium))
                    }
                    .foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help("Discard current interval")
            }
        }
        .padding(.top, 8)
    }

    private var focusSection: some View {
        HStack(spacing: 8) {
            Text("Focus")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)
                .frame(width: 36, alignment: .leading)

            HStack(spacing: 0) {
                ForEach(PomodoroMode.allCases) { mode in
                    Button {
                        model.setPomodoroMode(mode)
                    } label: {
                        Text(mode.title)
                            .font(.system(size: 12, weight: model.pomodoroMode == mode ? .semibold : .regular))
                            .foregroundStyle(model.pomodoroMode == mode ? .primary : .secondary)
                            .frame(maxWidth: .infinity)
                            .frame(height: 23)
                            .background(
                                RoundedRectangle(cornerRadius: 6, style: .continuous)
                                    .fill(model.pomodoroMode == mode ? Color(nsColor: .windowBackgroundColor) : Color.clear)
                                    .shadow(color: model.pomodoroMode == mode ? .black.opacity(0.08) : .clear, radius: 2, x: 0, y: 1)
                            )
                    }
                    .buttonStyle(.plain)
                }
            }
            .frame(width: 116)
            .padding(2)
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(Color(nsColor: .controlBackgroundColor))
            )
            Spacer(minLength: 0)

            Image(systemName: "bell")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(.tertiary)
        }
    }

    private var recentEntriesSection: some View {
        VStack(spacing: 5) {
            HStack {
                Text("Recent entries")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                Text(compactHours(model.recentEntriesHours))
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.secondary)
            }

            let visibleEntries = model.recentEntries
            if visibleEntries.isEmpty {
                HStack {
                    Text("No entries logged yet")
                        .font(.system(size: 12))
                        .foregroundStyle(.tertiary)
                    Spacer()
                }
                .frame(height: 22)
            } else {
                ForEach(visibleEntries) { entry in
                    EntryRow(entry: entry)
                }
            }
        }
    }

    private var separator: some View {
        Rectangle()
            .fill(Color(nsColor: .separatorColor).opacity(0.55))
            .frame(height: 0.5)
    }

    private var stateColor: Color {
        switch model.state {
        case .idle: .secondary
        case .running: .green
        case .paused: .orange
        }
    }

    private func hours(_ value: Double) -> String {
        if value.rounded(.down) == value {
            return "\(Int(value))h"
        }
        return String(format: "%.2fh", value)
    }

    private func compactHours(_ value: Double) -> String {
        let rounded = (value * 10).rounded() / 10
        if rounded.rounded(.down) == rounded {
            return "\(Int(rounded))h"
        }
        return String(format: "%.1fh", rounded)
    }
}

struct EntryRow: View {
    let entry: TimeEntry

    var body: some View {
        HStack(spacing: 7) {
            Capsule()
                .fill(Color.accentColor.opacity(0.72))
                .frame(width: 3, height: 18)

            Text(timeRange)
                .font(.system(size: 11))
                .monospacedDigit()
                .foregroundStyle(.secondary)
                .frame(width: 76, alignment: .leading)

            Text(entry.note)
                .font(.system(size: 12))
                .lineLimit(1)
                .truncationMode(.tail)

            Spacer(minLength: 5)

            Text(TimerModel.invoiceHours(entry.duration))
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(.secondary)
                .monospacedDigit()
        }
        .frame(height: 22)
    }

    private var timeRange: String {
        "\(Self.timeFormatter.string(from: entry.start))-\(Self.timeFormatter.string(from: entry.end))"
    }

    private static let timeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "H:mm"
        return formatter
    }()
}

struct TimerActionLabel: View {
    let title: String
    let systemImage: String
    let accent: Color
    let filled: Bool
    var fixedWidth: CGFloat?

    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: systemImage)
                .font(.system(size: 10, weight: .semibold))

            if !title.isEmpty {
                Text(title)
                    .font(.system(size: 12, weight: .semibold))
                    .lineLimit(1)
            }
        }
        .frame(maxWidth: fixedWidth == nil ? .infinity : nil)
        .frame(width: fixedWidth, height: 30)
        .foregroundStyle(filled ? .white : accent)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(filled ? accent : Color(nsColor: .controlBackgroundColor))
        )
        .contentShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

struct AnchoredTimerPanelView: View {
    @ObservedObject var model: TimerModel
    let arrowX: CGFloat
    var showsDetails = false

    var body: some View {
        VStack(spacing: 0) {
            Color.clear
                .overlay(alignment: .topLeading) {
                Notch()
                    .fill(Color(nsColor: .windowBackgroundColor))
                    .frame(width: 18, height: 9)
                        .offset(x: arrowX - 9)
            }
            .frame(width: AnchoredTimerPanelController.size.width, height: 9)

            TimerPopoverView(model: model, showsDetails: showsDetails)
                .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                .shadow(color: .black.opacity(0.18), radius: 12, x: 0, y: 6)
        }
        .frame(width: AnchoredTimerPanelController.size.width, height: AnchoredTimerPanelController.size.height, alignment: .top)
        .background(Color.clear)
    }
}

struct MenuBarScreenshotScene: View {
    @ObservedObject var model: TimerModel
    var showsDetails = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 0) {
                Spacer()
                StatusItemPreview(model: model)
                    .padding(.trailing, 18)
            }
            .frame(width: 430, height: 26)
            .background(Color(nsColor: .windowBackgroundColor))

            ZStack(alignment: .topTrailing) {
                Color(nsColor: .windowBackgroundColor).opacity(0.08)
                AnchoredTimerPanelView(
                    model: model,
                    arrowX: AnchoredTimerPanelController.size.width - 43,
                    showsDetails: showsDetails
                )
                    .padding(.trailing, 12)
            }
            .frame(width: 430, height: AnchoredTimerPanelController.size.height)
        }
        .frame(width: 430, height: AnchoredTimerPanelController.size.height + 26)
    }
}

struct StatusItemPreview: View {
    @ObservedObject var model: TimerModel

    var body: some View {
        Group {
            switch model.state {
            case .idle:
                Text("TC")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 6)
                    .frame(height: 22)
            case .running:
                Text(model.statusTitle)
                    .font(.system(size: 13, weight: .medium, design: .monospaced))
                    .foregroundStyle(.green)
                    .padding(.horizontal, 7)
                    .frame(height: 22)
            case .paused:
                Text(model.statusTitle)
                    .font(.system(size: 13, weight: .medium, design: .monospaced))
                    .foregroundStyle(.orange)
                    .padding(.horizontal, 7)
                    .frame(height: 22)
            }
        }
        .background(Color(nsColor: .controlBackgroundColor).opacity(model.state == .idle ? 0.2 : 1))
        .clipShape(RoundedRectangle(cornerRadius: 5, style: .continuous))
    }
}

struct Notch: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        path.move(to: CGPoint(x: rect.midX, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY))
        path.addLine(to: CGPoint(x: rect.minX, y: rect.maxY))
        path.closeSubpath()
        return path
    }
}

final class AnchoredPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }

    override func cancelOperation(_ sender: Any?) {
        orderOut(sender)
    }
}

struct AnchoredPanelPlacement: Equatable {
    let frame: NSRect
    let arrowX: CGFloat

    static func calculate(buttonRect: NSRect, visibleFrame: NSRect, panelSize: NSSize) -> AnchoredPanelPlacement {
        let preferredArrowX = panelSize.width - 43
        let rawX = buttonRect.midX - preferredArrowX
        let minX = visibleFrame.minX + 8
        let maxX = visibleFrame.maxX - panelSize.width - 8
        let x = min(max(rawX, minX), maxX)
        let arrowX = min(max(buttonRect.midX - x, 22), panelSize.width - 22)
        let y = buttonRect.minY - panelSize.height + 2

        return AnchoredPanelPlacement(
            frame: NSRect(origin: CGPoint(x: x, y: y), size: panelSize),
            arrowX: arrowX
        )
    }
}

enum PanelKeyDecision: Equatable {
    case closeAndConsume
    case passThrough

    static func keyDown(keyCode: UInt16) -> PanelKeyDecision {
        keyCode == 53 ? .closeAndConsume : .passThrough
    }
}

struct TimerPanelPresentationPolicy: Equatable {
    let hidesOnDeactivate: Bool
    let closesOnApplicationResignActive: Bool
    let windowLevel: NSWindow.Level

    static let menuBarAttachedPanel = TimerPanelPresentationPolicy(
        hidesOnDeactivate: false,
        closesOnApplicationResignActive: false,
        windowLevel: .popUpMenu
    )
}

struct StatusItemPresentation: Equatable {
    enum Emphasis: Equatable {
        case idle
        case running
        case paused
    }

    let title: String
    let emphasis: Emphasis
    let usesMonospacedDigits: Bool

    static func presentation(for model: TimerModel) -> StatusItemPresentation {
        switch model.state {
        case .idle:
            return StatusItemPresentation(
                title: model.statusTitle,
                emphasis: .idle,
                usesMonospacedDigits: false
            )
        case .running:
            return StatusItemPresentation(
                title: model.statusTitle,
                emphasis: .running,
                usesMonospacedDigits: true
            )
        case .paused:
            return StatusItemPresentation(
                title: model.statusTitle,
                emphasis: .paused,
                usesMonospacedDigits: true
            )
        }
    }
}

@MainActor
final class AnchoredTimerPanelController {
    static let size = NSSize(width: 326, height: 354)

    private let model: TimerModel
    private var panel: AnchoredPanel?
    private var globalEventMonitor: Any?
    private var localEventMonitor: Any?

    init(model: TimerModel) {
        self.model = model
    }

    var isShown: Bool {
        panel?.isVisible == true
    }

    func toggle(relativeTo button: NSStatusBarButton) {
        if isShown {
            close()
        } else {
            show(relativeTo: button)
        }
    }

    func close() {
        panel?.orderOut(nil)
        removeEventMonitors()
    }

    private func show(relativeTo button: NSStatusBarButton) {
        let panel = panel ?? makePanel(arrowX: Self.size.width - 43)
        self.panel = panel

        guard let window = button.window else {
            return
        }

        let buttonRect = window.convertToScreen(button.convert(button.bounds, to: nil))
        let screen = window.screen ?? NSScreen.main
        let visibleFrame = screen?.visibleFrame ?? buttonRect
        let placement = AnchoredPanelPlacement.calculate(
            buttonRect: buttonRect,
            visibleFrame: visibleFrame,
            panelSize: Self.size
        )

        panel.contentView = NSHostingView(rootView: AnchoredTimerPanelView(model: model, arrowX: placement.arrowX))
        panel.setFrame(placement.frame, display: true)
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        panel.orderFrontRegardless()
        DispatchQueue.main.async { [weak self] in
            self?.installEventMonitors()
        }
    }

    private func makePanel(arrowX: CGFloat) -> AnchoredPanel {
        let panel = AnchoredPanel(
            contentRect: NSRect(origin: .zero, size: Self.size),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        let policy = TimerPanelPresentationPolicy.menuBarAttachedPanel
        panel.animationBehavior = .none
        panel.backgroundColor = .clear
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]
        panel.contentView = NSHostingView(rootView: AnchoredTimerPanelView(model: model, arrowX: arrowX))
        panel.hasShadow = false
        panel.hidesOnDeactivate = policy.hidesOnDeactivate
        panel.isMovable = false
        panel.isOpaque = false
        panel.isReleasedWhenClosed = false
        panel.level = policy.windowLevel
        panel.titleVisibility = .hidden
        return panel
    }

    private func installEventMonitors() {
        removeEventMonitors()

        globalEventMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            Task { @MainActor in
                self?.close()
            }
        }

        localEventMonitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown]) { [weak self] event in
            if PanelKeyDecision.keyDown(keyCode: event.keyCode) == .closeAndConsume {
                Task { @MainActor in
                    self?.close()
                }
                return nil
            }
            return event
        }
    }

    private func removeEventMonitors() {
        if let globalEventMonitor {
            NSEvent.removeMonitor(globalEventMonitor)
            self.globalEventMonitor = nil
        }

        if let localEventMonitor {
            NSEvent.removeMonitor(localEventMonitor)
            self.localEventMonitor = nil
        }
    }
}

@MainActor
func renderScreenshot() throws {
    let args = CommandLine.arguments
    guard let pathIndex = args.firstIndex(of: "--render-screenshot")?.advanced(by: 1),
          args.indices.contains(pathIndex) else {
        throw CocoaError(.fileWriteInvalidFileName)
    }

    let stateArg = args.indices.contains(pathIndex + 1) ? args[pathIndex + 1] : "running"
    let state: TimerRunState = switch stateArg {
    case "idle": .idle
    case "paused": .paused
    default: .running
    }

    let view = MenuBarScreenshotScene(
        model: TimerModel.preview(state: state),
        showsDetails: CommandLine.arguments.contains("--details")
    )
    let renderer = ImageRenderer(content: view)
    renderer.scale = 2

    guard let image = renderer.nsImage,
          let tiff = image.tiffRepresentation,
          let bitmap = NSBitmapImageRep(data: tiff),
          let data = bitmap.representation(using: .png, properties: [:]) else {
        throw CocoaError(.fileWriteUnknown)
    }

    try data.write(to: URL(fileURLWithPath: args[pathIndex]))
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let model = TimerModel()
    private var statusItem: NSStatusItem?
    private lazy var panelController = AnchoredTimerPanelController(model: model)
    private var timer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)

        let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        self.statusItem = statusItem

        if let button = statusItem.button {
            button.target = self
            button.action = #selector(togglePopover)
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
            button.setButtonType(.momentaryPushIn)
        }

        model.onChange = { [weak self] in
            self?.updateStatusTitle()
        }

        updateStatusTitle()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.model.tick()
                self?.updateStatusTitle()
            }
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        timer?.invalidate()
    }

    func applicationDidResignActive(_ notification: Notification) {
        if TimerPanelPresentationPolicy.menuBarAttachedPanel.closesOnApplicationResignActive {
            panelController.close()
        }
    }

    @objc private func togglePopover() {
        guard let button = statusItem?.button else {
            return
        }

        if NSApp.currentEvent?.type == .rightMouseUp {
            showContextMenu(relativeTo: button)
            return
        }

        panelController.toggle(relativeTo: button)
    }

    @objc private func quitApp() {
        NSApp.terminate(nil)
    }

    private func showContextMenu(relativeTo button: NSStatusBarButton) {
        panelController.close()

        let menu = NSMenu()
        let quitItem = NSMenuItem(title: "Quit WhoaThere Timer", action: #selector(quitApp), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)
        menu.popUp(positioning: nil, at: NSPoint(x: 0, y: button.bounds.height + 2), in: button)
    }

    private func updateStatusTitle() {
        guard let button = statusItem?.button else {
            return
        }

        button.image = nil
        button.title = ""
        button.toolTip = "WhoaThere Timer"

        let presentation = StatusItemPresentation.presentation(for: model)
        let font: NSFont
        let color: NSColor
        switch presentation.emphasis {
        case .idle:
            statusItem?.length = NSStatusItem.variableLength
            button.imagePosition = .noImage
            font = .systemFont(ofSize: 12, weight: .semibold)
            color = .secondaryLabelColor
        case .running:
            statusItem?.length = NSStatusItem.variableLength
            button.imagePosition = .noImage
            font = .monospacedDigitSystemFont(ofSize: 13, weight: .medium)
            color = .systemGreen
        case .paused:
            statusItem?.length = NSStatusItem.variableLength
            button.imagePosition = .noImage
            font = .monospacedDigitSystemFont(ofSize: 13, weight: .medium)
            color = .systemOrange
        }

        button.attributedTitle = NSAttributedString(
            string: presentation.title,
            attributes: [
                .font: font,
                .foregroundColor: color
            ]
        )
    }
}

@MainActor
public func runWhoaThereTimerApp() {
    let app = NSApplication.shared

    if CommandLine.arguments.contains("--render-screenshot") {
        do {
            try renderScreenshot()
            exit(0)
        } catch {
            fputs("Screenshot render failed: \(error)\n", stderr)
            exit(1)
        }
    } else {
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }
}
