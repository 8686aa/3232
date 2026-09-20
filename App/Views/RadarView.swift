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

private enum RadarPainter {

    static func paint(_ ctx: inout GraphicsContext, size: CGSize, model: RadarModel) {
        let w = size.width
        let h = size.height
        guard w > 8, h > 8 else { return }

        let cx = w / 2
        let cy = h / 2
        let radius = min(w, h) * 0.46
        let t = model.time

        ctx.fill(Path(CGRect(origin: .zero, size: size)), with: .color(P.color(P.BG0)))

        // 背景径向辉光
        let bgR = radius * 1.5
        ctx.fill(Path(ellipseIn: CGRect(x: cx - bgR, y: cy - bgR, width: bgR * 2, height: bgR * 2)),
                 with: .radialGradient(Gradient(stops: [
                    .init(color: P.color(P.alpha(P.CYAN, 0x12)), location: 0),
                    .init(color: P.color(P.alpha(P.VIOLET, 0x0A)), location: 0.5),
                    .init(color: P.color(P.alpha(P.BG0, 0x00)), location: 1)
                 ]),
                 center: CGPoint(x: cx, y: cy), startRadius: 0, endRadius: bgR))

        drawStars(&ctx, w: w, h: h)
        drawGrid(&ctx, cx: cx, cy: cy, radius: radius, time: t)
        drawSweep(&ctx, cx: cx, cy: cy, radius: radius, model: model)
        drawLinks(&ctx, cx: cx, cy: cy, radius: radius, model: model)
        drawParticles(&ctx, cx: cx, cy: cy, radius: radius, model: model)
        drawCore(&ctx, cx: cx, cy: cy, live: model.live, time: t)
        drawNodes(&ctx, cx: cx, cy: cy, radius: radius, model: model, time: t)
    }

    // MARK: 微星点

    private static func drawStars(_ ctx: inout GraphicsContext, w: CGFloat, h: CGFloat) {
        var seed: UInt64 = 20260915
        func rnd() -> CGFloat {
            seed = seed &* 6364136223846793005 &+ 1442695040888963407
            return CGFloat((seed >> 33) % 100000) / 100000.0
        }
        let count = max(20, min(220, Int(w * h / 5200)))
        for _ in 0..<count {
            let x = rnd() * w
            let y = rnd() * h
            let a = Int(0x10 + rnd() * 0x30)
            ctx.fill(Path(ellipseIn: CGRect(x: x, y: y, width: 1.2, height: 1.2)),
                     with: .color(P.color(P.alpha(P.TXT, a))))
        }
    }

    // MARK: 网格

    private static func drawGrid(_ ctx: inout GraphicsContext, cx: CGFloat, cy: CGFloat,
                                 radius: CGFloat, time: CGFloat) {
        for i in 1...4 {
            let r = radius * CGFloat(i) / 4
            let outer = (i == 4)
            ctx.stroke(Path(ellipseIn: CGRect(x: cx - r, y: cy - r, width: r * 2, height: r * 2)),
                       with: .color(P.color(outer ? P.alpha(P.CYAN, 0x33) : P.alpha(P.GRID, 0x1A))),
                       lineWidth: outer ? 1.3 : 1)

            for k in 0..<48 {
                let a = CGFloat(k) / 48 * RadarModel.TAU
                let long = (k % 6 == 0)
                let len: CGFloat = long ? 6 : 3
                var tick = Path()
                tick.move(to: CGPoint(x: cx + cos(a) * r, y: cy + sin(a) * r))
                tick.addLine(to: CGPoint(x: cx + cos(a) * (r - len), y: cy + sin(a) * (r - len)))
                ctx.stroke(tick,
                           with: .color(P.color(long ? P.alpha(P.CYAN, 0x47) : P.alpha(P.GRID, 0x21))),
                           lineWidth: 1)
            }
        }

        // 十字对角线
        for k in 0..<4 {
            let a = CGFloat(k) / 4 * RadarModel.TAU + CGFloat.pi / 4
            var p = Path()
            p.move(to: CGPoint(x: cx + cos(a) * radius, y: cy + sin(a) * radius))
            p.addLine(to: CGPoint(x: cx - cos(a) * radius, y: cy - sin(a) * radius))
            ctx.stroke(p, with: .color(P.color(P.alpha(P.GRID, 0x17))), lineWidth: 1)
        }
    }

    // MARK: 扫描

    private static func drawSweep(_ ctx: inout GraphicsContext, cx: CGFloat, cy: CGFloat,
                                  radius: CGFloat, model: RadarModel) {
        let tail = CGFloat.pi * 0.62
        let steps = 30
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
            let alpha = Int(0.075 * (1 - Double(f0)) * 255)
            ctx.fill(wedge, with: .color(P.color(P.alpha(P.CYAN, alpha))))
        }

        var line = Path()
        line.move(to: CGPoint(x: cx, y: cy))
        line.addLine(to: CGPoint(x: cx + cos(ang) * radius, y: cy + sin(ang) * radius))
        ctx.stroke(line, with: .color(P.color(P.alpha(0xFFA0F5FF, 0x8C))), lineWidth: 1.6)
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
                let col = remotes[i].target ? P.AMBER : P.VIOLET
                ctx.stroke(p, with: .color(P.color(P.alpha(col, 0x1A))), lineWidth: 1)
            }
        }

        // 中心 → 客户端 虚线
        for d in model.devices {
            var p = Path()
            p.move(to: CGPoint(x: cx, y: cy))
            p.addLine(to: nodePoint(cx, cy, radius, d.angle, 1.0))
            ctx.stroke(p,
                       with: .color(P.color(P.alpha(P.TEAL, 0x3D))),
                       style: StrokeStyle(lineWidth: 1.2, dash: [4, 5]))
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
            let col = p.up ? P.TEAL : P.DOWN
            let pos = bez(p.t)
            let tail = bez(max(0, p.t - 0.09))

            var tp = Path()
            tp.move(to: tail)
            tp.addLine(to: pos)
            ctx.stroke(tp, with: .color(P.color(P.alpha(col, Int(0x8C * fade)))), lineWidth: 1.6)

            let sprite = 9 * (0.7 + fade * 0.6)
            glow(&ctx, at: pos, size: sprite, color: col, strength: fade)
        }

        // 落点涟漪
        for rp in model.ripples {
            guard rp.ri < model.remotes.count else { continue }
            let rem = model.remotes[rp.ri]
            let pt = nodePoint(cx, cy, radius, rem.angle, rem.r0)
            let rr = 6 + rp.t * 16
            ctx.stroke(Path(ellipseIn: CGRect(x: pt.x - rr, y: pt.y - rr, width: rr * 2, height: rr * 2)),
                       with: .color(P.color(P.alpha(P.AMBER, Int(0.55 * (1 - rp.t) * 255)))),
                       lineWidth: 1.2)
        }
    }

    // MARK: 核心

    private static func drawCore(_ ctx: inout GraphicsContext, cx: CGFloat, cy: CGFloat,
                                 live: Bool, time: CGFloat) {
        let halo = 124 * (1 + 0.05 * sin(time * 1.8))
        glow(&ctx, at: CGPoint(x: cx, y: cy), size: halo, color: P.TEAL, strength: 1)

        for i in 0..<3 {
            let prog = (time * 0.42 + CGFloat(i) / 3).truncatingRemainder(dividingBy: 1)
            let rr = 14 + prog * 46
            ctx.stroke(Path(ellipseIn: CGRect(x: cx - rr, y: cy - rr, width: rr * 2, height: rr * 2)),
                       with: .color(P.color(P.alpha(P.TEAL, Int(0.34 * (1 - prog) * 255)))),
                       lineWidth: 1.4)
        }

        glow(&ctx, at: CGPoint(x: cx, y: cy), size: 44, color: P.TEAL, strength: 1)
        ctx.fill(Path(ellipseIn: CGRect(x: cx - 3.7, y: cy - 3.7, width: 7.4, height: 7.4)),
                 with: .color(P.color(0xFFEAFFFB)))

        ctx.draw(Text(live ? "本机服务 · 监听中" : "本机服务 · 待机")
                    .font(Fonts.sans(9.5))
                    .foregroundColor(P.color(P.alpha(P.TEAL, 0xCC))),
                 at: CGPoint(x: cx, y: cy + 46), anchor: .center)
    }

    // MARK: 节点

    private static func drawNodes(_ ctx: inout GraphicsContext, cx: CGFloat, cy: CGFloat,
                                  radius: CGFloat, model: RadarModel, time: CGFloat) {
        // 远端
        for rem in model.remotes {
            let pt = nodePoint(cx, cy, radius, rem.angle, rem.r0)

            if rem.glow > 0.01 {
                glow(&ctx, at: pt, size: 30 + rem.glow * 22, color: rem.target ? P.AMBER : P.VIOLET,
                     strength: rem.glow)
            }

            if rem.target {
                let rr: CGFloat = 11
                let rot = time * 34 * CGFloat.pi / 180
                let span = CGFloat(252) * CGFloat.pi / 180
                var arc = Path()
                arc.addArc(center: pt, radius: rr,
                           startAngle: .radians(Double(rot)),
                           endAngle: .radians(Double(rot + span)),
                           clockwise: false)
                ctx.stroke(arc, with: .color(P.color(P.alpha(P.AMBER, 0xB3))), lineWidth: 1.3)
            }

            let core: CGFloat = rem.target ? 5 : 3.6
            ctx.fill(Path(ellipseIn: CGRect(x: pt.x - core, y: pt.y - core, width: core * 2, height: core * 2)),
                     with: .color(P.color(rem.target ? P.AMBER : 0xFFB9A8FF)))

            ctx.draw(Text(shortIp(rem.ip))
                        .font(Fonts.mono(9))
                        .foregroundColor(P.color(P.alpha(P.TXT_DIM, 0xE6))),
                     at: CGPoint(x: pt.x, y: pt.y - 12), anchor: .center)
            if rem.target {
                ctx.draw(Text("TARGET")
                            .font(Fonts.sans(8))
                            .foregroundColor(P.color(P.alpha(P.AMBER, 0x8C))),
                         at: CGPoint(x: pt.x, y: pt.y - 24), anchor: .center)
            }
        }

        // 客户端（热点设备）
        for (i, dev) in model.devices.enumerated() {
            let pt = nodePoint(cx, cy, radius, dev.angle, 1.0)

            let breath = 52 * (1 + 0.12 * sin(time * 2.2 + CGFloat(i)))
            glow(&ctx, at: pt, size: breath, color: P.CYAN, strength: 1)

            ctx.stroke(Path(ellipseIn: CGRect(x: pt.x - 6, y: pt.y - 6, width: 12, height: 12)),
                       with: .color(P.color(P.alpha(P.TEAL, 0x73))), lineWidth: 1.4)
            ctx.fill(Path(ellipseIn: CGRect(x: pt.x - 2.7, y: pt.y - 2.7, width: 5.4, height: 5.4)),
                     with: .color(P.color(P.TEAL)))

            ctx.draw(Text(dev.ip)
                        .font(Fonts.mono(10))
                        .foregroundColor(P.color(P.alpha(P.TXT, 0xEB))),
                     at: CGPoint(x: pt.x, y: pt.y + 20), anchor: .center)
            ctx.draw(Text("客户端")
                        .font(Fonts.sans(9))
                        .foregroundColor(P.color(P.alpha(P.TEAL, 0x8C))),
                     at: CGPoint(x: pt.x, y: pt.y + 33), anchor: .center)
        }
    }

    // MARK: 工具

    /// 椭圆收缩的节点坐标（x*1.16 / y*0.94）
    private static func nodePoint(_ cx: CGFloat, _ cy: CGFloat, _ radius: CGFloat,
                                  _ angle: CGFloat, _ factor: CGFloat) -> CGPoint {
        CGPoint(x: cx + cos(angle) * radius * factor * 1.16,
                y: cy + sin(angle) * radius * factor * 0.94)
    }

    /// 径向辉光贴图
    private static func glow(_ ctx: inout GraphicsContext, at pt: CGPoint,
                             size: CGFloat, color: UInt32, strength: CGFloat) {
        let r = max(size, 1) / 2
        let s = max(0, min(1, strength))
        let rect = CGRect(x: pt.x - r, y: pt.y - r, width: r * 2, height: r * 2)
        ctx.fill(Path(ellipseIn: rect),
                 with: .radialGradient(Gradient(stops: [
                    .init(color: P.color(P.alpha(color, Int(0xCC * s))), location: 0),
                    .init(color: P.color(P.alpha(color, Int(0x4D * s))), location: 0.38),
                    .init(color: P.color(P.alpha(color, 0)), location: 1)
                 ]),
                 center: pt, startRadius: 0, endRadius: r))
    }
}
