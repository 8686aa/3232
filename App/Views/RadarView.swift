import SwiftUI

/// 星图状态机（Device / Remote / Particle / Ripple）
final class RadarModel: @unchecked Sendable {
    struct Device {
        var ip: String
        var glow: CGFloat = 0
        var angle: CGFloat = 0
    }

    struct Remote {
        var ip: String
        var glow: CGFloat = 0
        var angle: CGFloat = 0
        var r0: CGFloat = 0.8
        var target: Bool = false
    }

    struct Particle {
        var di: Int
        var ri: Int
        var t: CGFloat
        var speed: CGFloat
        var up: Bool
    }

    struct Ripple {
        var ri: Int
        var t: CGFloat
    }

    static let TAU = CGFloat.pi * 2
    static let maxParticles = 240

    private(set) var devices: [Device] = []
    private(set) var remotes: [Remote] = []
    private(set) var particles: [Particle] = []
    private(set) var ripples: [Ripple] = []
    private(set) var sweep: CGFloat = 0
    private(set) var time: CGFloat = 0

    /// 是否处于监听中（决定扫描速度与粒子速度）
    var live = false

    private var last: Date?

    // MARK: - 数据装配

    func setDevices(_ ips: [String]) {
        let n = max(ips.count, 1)
        var out: [Device] = []
        for (i, ip) in ips.enumerated() {
            var d = Device(ip: ip)
            d.angle = -CGFloat.pi / 2 + CGFloat(i) / CGFloat(n) * Self.TAU + 0.35
            if let old = devices.first(where: { $0.ip == ip }) { d.glow = old.glow }
            out.append(d)
        }
        devices = out
    }

    func setRemotes(_ ips: [String], targets: Set<String> = []) {
        var out: [Remote] = []
        for ip in ips {
            var r = Remote(ip: ip)
            r.angle = Self.hash01(ip) * Self.TAU
            r.r0 = 0.74 + Self.hash01(ip + "#r") * 0.2
            r.target = targets.contains(ip)
            out.append(r)
        }
        remotes = out
    }

    func clear() {
        devices.removeAll()
        remotes.removeAll()
        particles.removeAll()
        ripples.removeAll()
    }

    /// 一次收发：两端点亮 + 生成粒子
    func emit(up: Bool, deviceIp: String, remoteIp: String) {
        guard let di = devices.firstIndex(where: { $0.ip == deviceIp }),
              let ri = remotes.firstIndex(where: { $0.ip == remoteIp }) else { return }
        devices[di].glow = min(1, devices[di].glow + 0.5)
        remotes[ri].glow = min(1, remotes[ri].glow + 0.5)
        if particles.count >= Self.maxParticles { particles.removeFirst() }
        particles.append(Particle(di: di,
                                  ri: ri,
                                  t: 0,
                                  speed: 1.5 + CGFloat.random(in: 0...1) * 0.7,
                                  up: up))
    }

    // MARK: - 帧推进

    func advance(to now: Date) {
        let dt: CGFloat
        if let l = last {
            dt = min(max(CGFloat(now.timeIntervalSince(l)), 0), 0.05)
        } else {
            dt = 0
        }
        last = now
        time += dt

        if live || !particles.isEmpty { sweep += dt * 1.05 }
        if sweep > Self.TAU { sweep -= Self.TAU }

        let factor: CGFloat = live ? 1 : 0.4
        for i in particles.indices {
            particles[i].t += dt * particles[i].speed * factor
        }

        var finished: [Int] = []
        for (i, p) in particles.enumerated() where p.t >= 1 {
            ripples.append(Ripple(ri: p.ri, t: 0))
            finished.append(i)
        }
        for i in finished.reversed() { particles.remove(at: i) }

        for i in ripples.indices { ripples[i].t += dt * 2.1 }
        ripples.removeAll { $0.t >= 1 }

        for i in devices.indices { devices[i].glow = max(0, devices[i].glow - dt * 0.8) }
        for i in remotes.indices { remotes[i].glow = max(0, remotes[i].glow - dt * 0.02) }
    }

    // MARK: - 工具

    /// FNV-1a 32 位 → 0..1
    static func hash01(_ s: String) -> CGFloat {
        var h: UInt32 = 2166136261
        for b in s.utf8 {
            h ^= UInt32(b)
            h = h &* 16777619
        }
        return CGFloat(h % 10000) / 10000.0
    }
}

// MARK: - 视图

struct RadarView: View {
    let model: RadarModel

    var body: some View {
        TimelineView(.animation) { tl in
            Canvas(rendersAsynchronously: false) { ctx, size in
                model.advance(to: tl.date)
                RadarPainter.paint(&ctx, size: size, model: model)
            }
        }
    }
}

// MARK: - 绘制

/// 全部用系统语义色，浅色/深色底都能看清；只画同心圆、刻度、连线、光点，不做装饰性元素。
private enum RadarPainter {

    private static var grid: Color { Color.gray.opacity(0.30) }
    private static var gridSoft: Color { Color.gray.opacity(0.22) }
    private static var tickColor: Color { Color.gray.opacity(0.50) }
    private static var labelColor: Color { Color.secondary }

    static func paint(_ ctx: inout GraphicsContext, size: CGSize, model: RadarModel) {
        let w = size.width
        let h = size.height
        guard w > 8, h > 8 else { return }

        let cx = w / 2
        let cy = h / 2
        let radius = min(w, h) * 0.42
        let t = model.time

        drawGrid(&ctx, cx: cx, cy: cy, radius: radius)
        drawSweep(&ctx, cx: cx, cy: cy, radius: radius, model: model)
        drawLinks(&ctx, cx: cx, cy: cy, radius: radius, model: model)
        drawParticles(&ctx, cx: cx, cy: cy, radius: radius, model: model)
        drawCore(&ctx, cx: cx, cy: cy, live: model.live, time: t)
        drawNodes(&ctx, cx: cx, cy: cy, radius: radius, model: model, time: t)
    }

    // MARK: 网格：4 圈同心圆 + 十字线 + 外圈刻度

    private static func drawGrid(_ ctx: inout GraphicsContext, cx: CGFloat, cy: CGFloat, radius: CGFloat) {
        for i in 1...4 {
            let r = radius * CGFloat(i) / 4
            ctx.stroke(Path(ellipseIn: CGRect(x: cx - r, y: cy - r, width: r * 2, height: r * 2)),
                       with: .color(i == 4 ? Color.blue.opacity(0.35) : grid),
                       lineWidth: 1)
        }

        for k in 0..<4 {
            let a = CGFloat(k) / 4 * RadarModel.TAU + CGFloat.pi / 4
            var line = Path()
            line.move(to: CGPoint(x: cx + cos(a) * radius, y: cy + sin(a) * radius))
            line.addLine(to: CGPoint(x: cx - cos(a) * radius, y: cy - sin(a) * radius))
            ctx.stroke(line, with: .color(gridSoft), lineWidth: 1)
        }

        for k in 0..<12 {
            let a = CGFloat(k) / 12 * RadarModel.TAU
            var tick = Path()
            tick.move(to: CGPoint(x: cx + cos(a) * radius, y: cy + sin(a) * radius))
            tick.addLine(to: CGPoint(x: cx + cos(a) * (radius - 6), y: cy + sin(a) * (radius - 6)))
            ctx.stroke(tick, with: .color(tickColor), lineWidth: 1)
        }
    }

    // MARK: 扫描

    private static func drawSweep(_ ctx: inout GraphicsContext, cx: CGFloat, cy: CGFloat,
                                  radius: CGFloat, model: RadarModel) {
        let tail = CGFloat.pi * 0.55
        let steps = 20
        let ang = model.sweep
        for i in 0..<steps {
            let f0 = CGFloat(i) / CGFloat(steps)
            let f1 = CGFloat(i + 1) / CGFloat(steps)
            let a0 = ang - tail * f0
            let a1 = ang - tail * f1
            var wedge = Path()
            wedge.move(to: CGPoint(x: cx, y: cy))
            wedge.addLine(to: CGPoint(x: cx + cos(a1) * radius, y: cy + sin(a1) * radius))
            wedge.addLine(to: CGPoint(x: cx + cos(a0) * radius, y: cy + sin(a0) * radius))
            wedge.closeSubpath()
            ctx.fill(wedge, with: .color(Color.blue.opacity(Double(0.10 * (1 - f0)))))
        }

        var line = Path()
        line.move(to: CGPoint(x: cx, y: cy))
        line.addLine(to: CGPoint(x: cx + cos(ang) * radius, y: cy + sin(ang) * radius))
        ctx.stroke(line, with: .color(Color.blue.opacity(0.55)), lineWidth: 1.5)
    }

    // MARK: 连线

    private static func drawLinks(_ ctx: inout GraphicsContext, cx: CGFloat, cy: CGFloat,
                                  radius: CGFloat, model: RadarModel) {
        // 远端之间的弱连接
        let remotes = model.remotes
        if remotes.count > 1 {
            for i in 0..<(remotes.count - 1) {
                let a = nodePoint(cx, cy, radius, remotes[i].angle, remotes[i].r0)
                let b = nodePoint(cx, cy, radius, remotes[i + 1].angle, remotes[i + 1].r0)
                var p = Path()
                p.move(to: a)
                p.addLine(to: b)
                ctx.stroke(p, with: .color(gridSoft), lineWidth: 1)
            }
        }

        // 中心 → 客户端 虚线
        for d in model.devices {
            var p = Path()
            p.move(to: CGPoint(x: cx, y: cy))
            p.addLine(to: nodePoint(cx, cy, radius, d.angle, 1.0))
            ctx.stroke(p,
                       with: .color(Color.blue.opacity(0.28)),
                       style: StrokeStyle(lineWidth: 1, dash: [4, 5]))
        }
    }

    // MARK: 粒子

    private static func drawParticles(_ ctx: inout GraphicsContext, cx: CGFloat, cy: CGFloat,
                                      radius: CGFloat, model: RadarModel) {
        for p in model.particles {
            guard p.di < model.devices.count, p.ri < model.remotes.count else { continue }
            let dev = model.devices[p.di]
            let rem = model.remotes[p.ri]
            let a = nodePoint(cx, cy, radius, dev.angle, 1.0)
            let b = nodePoint(cx, cy, radius, rem.angle, rem.r0)

            let dx = b.x - a.x
            let dy = b.y - a.y
            let len = max(1, sqrt(dx * dx + dy * dy))
            let bow: CGFloat = 14
            let ctrl = CGPoint(x: (a.x + b.x) / 2 - dy / len * bow,
                               y: (a.y + b.y) / 2 + dx / len * bow)

            func bez(_ tt: CGFloat) -> CGPoint {
                let mt = 1 - tt
                return CGPoint(x: mt * mt * a.x + 2 * mt * tt * ctrl.x + tt * tt * b.x,
                               y: mt * mt * a.y + 2 * mt * tt * ctrl.y + tt * tt * b.y)
            }

            let fade = sin(CGFloat.pi * max(0, min(1, p.t)))
            let color = p.up ? Palette.up : Palette.down
            let pos = bez(p.t)
            let tailPos = bez(max(0, p.t - 0.09))

            var trail = Path()
            trail.move(to: tailPos)
            trail.addLine(to: pos)
            ctx.stroke(trail, with: .color(color.opacity(Double(0.55 * fade))), lineWidth: 1.6)

            glow(&ctx, at: pos, size: 9 * (0.7 + fade * 0.6), color: color, strength: fade)
        }

        // 落点涟漪
        for rp in model.ripples {
            guard rp.ri < model.remotes.count else { continue }
            let rem = model.remotes[rp.ri]
            let pt = nodePoint(cx, cy, radius, rem.angle, rem.r0)
            let rr = 6 + rp.t * 14
            ctx.stroke(Path(ellipseIn: CGRect(x: pt.x - rr, y: pt.y - rr, width: rr * 2, height: rr * 2)),
                       with: .color(Palette.down.opacity(Double(0.5 * (1 - rp.t)))),
                       lineWidth: 1)
        }
    }

    // MARK: 核心

    private static func drawCore(_ ctx: inout GraphicsContext, cx: CGFloat, cy: CGFloat,
                                 live: Bool, time: CGFloat) {
        let color = live ? Color.blue : Color.gray
        glow(&ctx, at: CGPoint(x: cx, y: cy), size: 60, color: color, strength: live ? 0.9 : 0.5)

        // 监听中才有向外扩散的脉冲
        if live {
            for i in 0..<3 {
                let prog = (time * 0.42 + CGFloat(i) / 3).truncatingRemainder(dividingBy: 1)
                let rr = 12 + prog * 40
                ctx.stroke(Path(ellipseIn: CGRect(x: cx - rr, y: cy - rr, width: rr * 2, height: rr * 2)),
                           with: .color(color.opacity(Double(0.30 * (1 - prog)))),
                           lineWidth: 1.2)
            }
        }

        ctx.fill(Path(ellipseIn: CGRect(x: cx - 5, y: cy - 5, width: 10, height: 10)),
                 with: .color(color))

        ctx.draw(Text(live ? "本机服务 · 监听中" : "本机服务 · 待机")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundColor(labelColor),
                 at: CGPoint(x: cx, y: cy + 36), anchor: .center)
    }

    // MARK: 节点

    private static func drawNodes(_ ctx: inout GraphicsContext, cx: CGFloat, cy: CGFloat,
                                  radius: CGFloat, model: RadarModel, time: CGFloat) {
        // 远端
        for rem in model.remotes {
            let pt = nodePoint(cx, cy, radius, rem.angle, rem.r0)
            let color = rem.target ? Palette.down : Color.purple

            if rem.glow > 0.01 {
                glow(&ctx, at: pt, size: 26 + rem.glow * 18, color: color, strength: rem.glow)
            }

            let core: CGFloat = rem.target ? 4.5 : 3.5
            ctx.fill(Path(ellipseIn: CGRect(x: pt.x - core, y: pt.y - core, width: core * 2, height: core * 2)),
                     with: .color(color))

            ctx.draw(Text(shortIp(rem.ip))
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundColor(labelColor),
                     at: CGPoint(x: pt.x, y: pt.y - 12), anchor: .center)
        }

        // 客户端（热点设备）
        for (i, dev) in model.devices.enumerated() {
            let pt = nodePoint(cx, cy, radius, dev.angle, 1.0)

            let breath = 30 * (1 + 0.12 * sin(time * 2.2 + CGFloat(i)))
            glow(&ctx, at: pt, size: breath, color: Color.blue, strength: 0.75)

            ctx.stroke(Path(ellipseIn: CGRect(x: pt.x - 6, y: pt.y - 6, width: 12, height: 12)),
                       with: .color(Color.blue.opacity(0.6)), lineWidth: 1.4)
            ctx.fill(Path(ellipseIn: CGRect(x: pt.x - 2.6, y: pt.y - 2.6, width: 5.2, height: 5.2)),
                     with: .color(Color.blue))

            ctx.draw(Text(dev.ip)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(Color.primary),
                     at: CGPoint(x: pt.x, y: pt.y + 19), anchor: .center)
            ctx.draw(Text("客户端")
                        .font(.system(size: 9))
                        .foregroundColor(labelColor),
                     at: CGPoint(x: pt.x, y: pt.y + 32), anchor: .center)
        }
    }

    // MARK: 工具

    /// 椭圆收缩的节点坐标（x*1.16 / y*0.94）
    private static func nodePoint(_ cx: CGFloat, _ cy: CGFloat, _ radius: CGFloat,
                                  _ angle: CGFloat, _ factor: CGFloat) -> CGPoint {
        CGPoint(x: cx + cos(angle) * radius * factor * 1.16,
                y: cy + sin(angle) * radius * factor * 0.94)
    }

    /// 柔和径向光斑
    private static func glow(_ ctx: inout GraphicsContext, at pt: CGPoint,
                             size: CGFloat, color: Color, strength: CGFloat) {
        let r = max(size, 1) / 2
        let s = Double(max(0, min(1, strength)))
        ctx.fill(Path(ellipseIn: CGRect(x: pt.x - r, y: pt.y - r, width: r * 2, height: r * 2)),
                 with: .radialGradient(Gradient(stops: [
                    .init(color: color.opacity(0.35 * s), location: 0),
                    .init(color: color.opacity(0), location: 1)
                 ]),
                 center: pt, startRadius: 0, endRadius: r))
    }
}
