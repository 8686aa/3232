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

        series(&g, pts: downPts, line: P.DOWN, gradTop: P.VIOLET, plotH: plotH, padT: padT, lineWidth: 1.7)
        series(&g, pts: upPts, line: P.TEAL, gradTop: P.CYAN, plotH: plotH, padT: padT, lineWidth: 1.7)

        // 端点光点
        let tipUp = upPts[n - 1]
        let pulse = 5.5 * (1 + 0.35 * sin(CGFloat(now.timeIntervalSinceReferenceDate) * 4))
        glowDot(&g, at: tipUp, size: pulse * 2, color: P.TEAL)
        g.fill(Path(ellipseIn: CGRect(x: tipUp.x - 1.3, y: tipUp.y - 1.3, width: 2.6, height: 2.6)),
               with: .color(P.color(P.alpha(P.TEAL, 0xFF))))

        let tipDown = downPts[n - 1]
        glowDot(&g, at: tipDown, size: pulse * 2, color: P.DOWN)
        g.fill(Path(ellipseIn: CGRect(x: tipDown.x - 1.3, y: tipDown.y - 1.3, width: 2.6, height: 2.6)),
               with: .color(P.color(P.alpha(P.DOWN, 0xFF))))
    }

    // MARK: 网格

    private static func drawGrid(_ ctx: inout GraphicsContext, w: CGFloat, padT: CGFloat,
                                 padL: CGFloat, padR: CGFloat, plotW: CGFloat, plotH: CGFloat,
                                 maxValue: CGFloat) {
        for i in 0...4 {
            let y = padT + plotH * CGFloat(i) / 4
            let solid = (i == 3)
            var line = Path()
            line.move(to: CGPoint(x: padL, y: y))
            line.addLine(to: CGPoint(x: w - padR, y: y))
            ctx.stroke(line,
                       with: .color(P.color(P.alpha(P.GRID, solid ? 0x33 : 0x1A))),
                       style: StrokeStyle(lineWidth: 1, dash: solid ? [] : [3, 5]))

            let value = maxValue * (1 - CGFloat(i) / 4)
            ctx.draw(Text(String(format: "%.0f", value))
                        .font(Fonts.mono(8.5))
                        .foregroundColor(P.color(P.alpha(P.TXT_MUTE, 0xCC))),
                     at: CGPoint(x: w - padR + 24, y: y), anchor: .center)
        }

        for i in 0...3 {
            let x = padL + plotW * CGFloat(i) / 3
            var line = Path()
            line.move(to: CGPoint(x: x, y: padT))
            line.addLine(to: CGPoint(x: x, y: padT + plotH))
            ctx.stroke(line,
                       with: .color(P.color(P.alpha(P.GRID, 0x17))),
                       style: StrokeStyle(lineWidth: 1, dash: [2, 6]))
        }

        ctx.draw(Text("峰值 \(Int(maxValue)) Kbps")
                    .font(Fonts.mono(9))
                    .foregroundColor(P.color(P.alpha(P.TXT_MUTE, 0xE6))),
                 at: CGPoint(x: padL + 2, y: padT - 11), anchor: .leading)
    }

    // MARK: 单条曲线（面积 + 泛光 + 实体）

    private static func series(_ ctx: inout GraphicsContext, pts: [CGPoint], line: UInt32,
                               gradTop: UInt32, plotH: CGFloat, padT: CGFloat, lineWidth: CGFloat) {
        guard pts.count > 1 else { return }

        let curve = smoothPath(pts)

        var area = curve
        area.addLine(to: CGPoint(x: pts[pts.count - 1].x, y: padT + plotH))
        area.addLine(to: CGPoint(x: pts[0].x, y: padT + plotH))
        area.closeSubpath()
        ctx.fill(area, with: .linearGradient(Gradient(stops: [
            .init(color: P.color(P.alpha(gradTop, 0x4D)), location: 0),
            .init(color: P.color(P.alpha(line, 0x1A)), location: 0.6),
            .init(color: P.color(P.alpha(gradTop, 0x00)), location: 1)
        ]),
        startPoint: CGPoint(x: 0, y: padT),
        endPoint: CGPoint(x: 0, y: padT + plotH)))

        ctx.stroke(curve, with: .color(P.color(P.alpha(line, 0x3D))), lineWidth: lineWidth + 3.3)
        ctx.stroke(curve, with: .color(P.color(P.alpha(line, 0xF2))), lineWidth: lineWidth)
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

    private static func glowDot(_ ctx: inout GraphicsContext, at pt: CGPoint,
                                size: CGFloat, color: UInt32) {
        let r = max(size, 1) / 2
        ctx.fill(Path(ellipseIn: CGRect(x: pt.x - r, y: pt.y - r, width: r * 2, height: r * 2)),
                 with: .radialGradient(Gradient(stops: [
                    .init(color: P.color(P.alpha(color, 0x2E)), location: 0),
                    .init(color: P.color(P.alpha(color, 0x00)), location: 1)
                 ]),
                 center: pt, startRadius: 0, endRadius: r))
    }
}
