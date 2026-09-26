import SwiftUI

/// 波形采样缓冲（环形数组）
final class WaveModel: @unchecked Sendable {
    static let n = 40

    private(set) var upSamples = [CGFloat](repeating: 0, count: WaveModel.n)
    private(set) var downSamples = [CGFloat](repeating: 0, count: WaveModel.n)
    private(set) var pushAt = Date()

    func push(up: CGFloat, down: CGFloat) {
        upSamples.removeFirst()
        upSamples.append(up)
        downSamples.removeFirst()
        downSamples.append(down)
        pushAt = Date()
    }

    func reset() {
        upSamples = [CGFloat](repeating: 0, count: WaveModel.n)
        downSamples = [CGFloat](repeating: 0, count: WaveModel.n)
        pushAt = Date()
    }
}

struct WaveView: View {
    let model: WaveModel

    var body: some View {
        TimelineView(.animation) { tl in
            Canvas { ctx, size in
                WavePainter.paint(&ctx, size: size, model: model, now: tl.date)
            }
        }
    }
}

/// 上行/下行两条曲线，语义色 + 浅色网格，不做泛光与装饰。
private enum WavePainter {

    static func paint(_ ctx: inout GraphicsContext, size: CGSize, model: WaveModel, now: Date) {
        let w = size.width
        let h = size.height
        guard w > 24, h > 24 else { return }

        let padT: CGFloat = 20
        let padB: CGFloat = 6
        let padL: CGFloat = 6
        let padR: CGFloat = 46
        let plotW = max(1, w - padL - padR)
        let plotH = max(1, h - padT - padB)
        let n = WaveModel.n
        let dx = plotW / CGFloat(n - 1)

        // 自动量程
        let peak = max(40, (model.upSamples + model.downSamples).max() ?? 40)
        let nice = pow(10, floor(log10(Double(peak))))
        let maxValue = max(40, CGFloat(ceil(Double(peak) * 1.18 / nice) * nice))

        // 滚动缓动
        let p = min(1, max(0, CGFloat(now.timeIntervalSince(model.pushAt)) / 0.28))
        let eased = 1 - pow(1 - p, 3)
        let shift = (1 - eased) * dx

        func pt(_ i: Int, _ v: CGFloat) -> CGPoint {
            CGPoint(x: padL - shift + CGFloat(i) * dx,
                    y: padT + plotH * (1 - min(1, max(0, v / maxValue))))
        }

        drawGrid(&ctx, w: w, padT: padT, padL: padL, padR: padR, plotW: plotW, plotH: plotH, maxValue: maxValue)

        // 裁剪到绘图区
        var g = ctx
        g.clip(to: Path(CGRect(x: padL, y: 0, width: plotW, height: h)))

        let upPts = (0..<n).map { pt($0, model.upSamples[$0]) }
        let downPts = (0..<n).map { pt($0, model.downSamples[$0]) }

        series(&g, pts: downPts, color: Palette.down, plotH: plotH, padT: padT)
        series(&g, pts: upPts, color: Palette.up, plotH: plotH, padT: padT)

        // 端点圆点
        dot(&g, at: upPts[n - 1], color: Palette.up)
        dot(&g, at: downPts[n - 1], color: Palette.down)
    }

    // MARK: 网格

    private static func drawGrid(_ ctx: inout GraphicsContext, w: CGFloat, padT: CGFloat,
                                 padL: CGFloat, padR: CGFloat, plotW: CGFloat, plotH: CGFloat,
                                 maxValue: CGFloat) {
        for i in 0...4 {
            let y = padT + plotH * CGFloat(i) / 4
            var line = Path()
            line.move(to: CGPoint(x: padL, y: y))
            line.addLine(to: CGPoint(x: w - padR, y: y))
            ctx.stroke(line,
                       with: .color(Color.gray.opacity(0.30)),
                       style: StrokeStyle(lineWidth: 1, dash: i == 4 ? [] : [3, 4]))

            let value = maxValue * (1 - CGFloat(i) / 4)
            ctx.draw(Text(String(format: "%.0f", value))
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundColor(Color.secondary),
                     at: CGPoint(x: w - padR + 24, y: y), anchor: .center)
        }

        for i in 0...3 {
            let x = padL + plotW * CGFloat(i) / 3
            var line = Path()
            line.move(to: CGPoint(x: x, y: padT))
            line.addLine(to: CGPoint(x: x, y: padT + plotH))
            ctx.stroke(line,
                       with: .color(Color.gray.opacity(0.18)),
                       style: StrokeStyle(lineWidth: 1, dash: [2, 6]))
        }

        ctx.draw(Text("峰值 \(Int(maxValue)) Kbps")
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(Color.secondary),
                 at: CGPoint(x: padL + 2, y: padT - 11), anchor: .leading)
    }

    // MARK: 单条曲线（面积 + 实体）

    private static func series(_ ctx: inout GraphicsContext, pts: [CGPoint], color: Color,
                               plotH: CGFloat, padT: CGFloat) {
        guard pts.count > 1 else { return }

        let curve = smoothPath(pts)

        var area = curve
        area.addLine(to: CGPoint(x: pts[pts.count - 1].x, y: padT + plotH))
        area.addLine(to: CGPoint(x: pts[0].x, y: padT + plotH))
        area.closeSubpath()
        ctx.fill(area, with: .linearGradient(Gradient(stops: [
            .init(color: color.opacity(0.22), location: 0),
            .init(color: color.opacity(0), location: 1)
        ]),
        startPoint: CGPoint(x: 0, y: padT),
        endPoint: CGPoint(x: 0, y: padT + plotH)))

        ctx.stroke(curve, with: .color(color), style: StrokeStyle(lineWidth: 2, lineJoin: .round))
    }

    /// Catmull-Rom → 三次贝塞尔
    private static func smoothPath(_ pts: [CGPoint]) -> Path {
        var path = Path()
        guard pts.count > 1 else { return path }
        path.move(to: pts[0])
        for i in 0..<(pts.count - 1) {
            let p0 = pts[max(0, i - 1)]
            let p1 = pts[i]
            let p2 = pts[i + 1]
            let p3 = pts[min(pts.count - 1, i + 2)]
            let c1 = CGPoint(x: p1.x + (p2.x - p0.x) / 6, y: p1.y + (p2.y - p0.y) / 6)
            let c2 = CGPoint(x: p2.x - (p3.x - p1.x) / 6, y: p2.y - (p3.y - p1.y) / 6)
            path.addCurve(to: p2, control1: c1, control2: c2)
        }
        return path
    }

    private static func dot(_ ctx: inout GraphicsContext, at pt: CGPoint, color: Color) {
        ctx.fill(Path(ellipseIn: CGRect(x: pt.x - 3, y: pt.y - 3, width: 6, height: 6)),
                 with: .color(color))
    }
}
