import SwiftUI

/// 数据页：报文流与运行日志，用系统分段控件切换。
struct DataPage: View {
    @ObservedObject var model: EngineViewModel

    private enum Kind: String, CaseIterable, Identifiable {
        case packets = "报文"
        case logs = "日志"
        var id: String { rawValue }
    }

    @State private var kind: Kind = .packets

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Picker("内容", selection: $kind) {
                        ForEach(Kind.allCases) { item in
                            Text(item.rawValue).tag(item)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                }

                switch kind {
                case .packets:
                    packetSection
                case .logs:
                    logSection
                }
            }
            .navigationTitle("数据")
        }
    }

    // MARK: - 报文流

    @ViewBuilder
    private var packetSection: some View {
        Section("报文流（\(model.rows.count) 条）") {
            if model.rows.isEmpty {
                emptyHint("暂无报文，开始监听后会实时刷新")
            } else {
                ForEach(model.rows) { row in
                    PacketRowView(info: row)
                }
            }
        }
    }

    // MARK: - 日志

    @ViewBuilder
    private var logSection: some View {
        Section("运行日志（\(model.lines.count) 条）") {
            if displayedLines.isEmpty {
                emptyHint("暂无日志")
            } else {
                ForEach(displayedLines) { line in
                    LogRowView(line: line)
                }
            }
        }
    }

    /// 只渲染最后 120 条，避免长列表拖慢滚动
    private var displayedLines: [EngineViewModel.LogLine] {
        model.lines.count > 120 ? Array(model.lines.suffix(120)) : model.lines
    }

    private func emptyHint(_ text: String) -> some View {
        Text(text)
            .font(.footnote)
            .foregroundStyle(.secondary)
    }
}

/// 单条日志：左侧级别色点 + 正文 + 时间。
private struct LogRowView: View {
    let line: EngineViewModel.LogLine

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Circle()
                .fill(levelColor(line.level))
                .frame(width: 6, height: 6)
                .padding(.top, 6)

            VStack(alignment: .leading, spacing: 2) {
                Text(line.msg)
                    .font(.footnote)
                Text(fmtTime(line.at))
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
    }
}
