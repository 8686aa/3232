import Foundation

/// 一条待上报的 UDP 报文：四元组 + 载荷。
///
/// 与 `SOCKS5UDPRelay.onDatagram` 交出来的东西一一对应，只是把「谁发给谁」
/// 补全成 IP 头需要的形状 —— 上行时源是客户端，下行时源是远端。
public struct UDPPacket: Equatable {
    public let src: String
    public let dst: String
    public let sport: UInt16
    public let dport: UInt16
    public let payload: [UInt8]

    public init(src: String, dst: String, sport: UInt16, dport: UInt16, payload: [UInt8]) {
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.payload = payload
    }
}

/// 上报三道闸门里的 ②③。
///
/// ①「白名单」在采集侧天然成立：iOS 只看得见 SOCKS5 客户端的 UDP，
/// 不参与的手机地址根本到不了这里。剩下两道必须自己补：
///
/// - ② 只上报「远端为公网」的 UDP。局域网互访、投屏、AirPlay 与游戏无关；
/// - ③ 只有**按序命中握手长度签名**的流才认定是对局流。对局服务器的握手是
///   固定的一串长度序列，签名凑齐前先缓冲、凑齐后整段按到达顺序补发，
///   于是握手阶段的包一个都不会丢。
///
/// `feed` 返回本次该进上报队列的报文：通常是空数组或只有当前这一个包，
/// 只有签名刚好凑齐那一刻才是「缓冲的整段」。
public final class UploadGate {
    /// 握手签名（是否上行, UDP 载荷长度）。只存在于引擎内部，不下发界面。
    ///
    /// 注意方向：7 项里有 4 项是**下行**，所以采集必须上下行都接，
    /// 只盯上行永远凑不齐，整条流都会被当成随机 UDP 丢掉。
    public static let handshakePrefix: [(up: Bool, length: Int)] = [
        (true, 33), (false, 25), (true, 33), (false, 25),
        (true, 35), (false, 31), (false, 10),
    ]
    /// 缓冲到这么多包还没凑齐签名，就判定为非会话流并放弃该流
    public static let handshakeProbeLimit = 64
    /// 流表上限，满了先清空闲流
    public static let maxTrackedFlows = 1024
    /// 多久没活动的流算空闲
    public static let flowIdleSeconds: TimeInterval = 60

    /// 刚识别出一条对局流时回调（每条流一次）。回调里只该做日志这类轻活。
    public var onGame: ((String) -> Void)?

    /// 界面上要看的累计量
    public private(set) var upCount = 0
    public private(set) var downCount = 0
    public private(set) var upBytes = 0
    public private(set) var downBytes = 0
    /// 因「远端是内网」被留下的报文数
    public private(set) var ignored = 0
    /// 被签名门挡下的报文数（含超限放弃时整段丢弃的）
    public private(set) var signatureFiltered = 0
    /// 已识别的对局流总数
    public private(set) var gameFlows = 0

    private struct Flow {
        /// 已按序命中的签名项数
        var matched = 0
        /// 是否已判定为对局流
        var game = false
        var lastSeen: TimeInterval
        /// 命中前缓冲的报文，凑齐签名后按到达顺序整段补发
        var pending: [UDPPacket] = []
    }

    private var flows: [String: Flow] = [:]
    private let clock: () -> TimeInterval

    public init(clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.clock = clock
    }

    /// 正在跟踪的流数（签名门还没放弃的）
    public var trackedFlows: Int { flows.count }

    /// 收一条报文。`up` 表示客户端发往远端。
    public func feed(_ packet: UDPPacket, up: Bool) -> [UDPPacket] {
        let payloadLength = packet.payload.count
        let now = clock()
        if up {
            upCount += 1
            upBytes += payloadLength + IPDatagram.ipUDPHeaderBytes
        } else {
            downCount += 1
            downBytes += payloadLength + IPDatagram.ipUDPHeaderBytes
        }

        // ② 远端为内网的不上报
        let remote = up ? packet.dst : packet.src
        let client = up ? packet.src : packet.dst
        guard !Self.isPrivate(remote) else {
            ignored += 1
            return []
        }

        let localPort = up ? packet.sport : packet.dport
        let port = up ? packet.dport : packet.sport
        let key = "\(client)|\(localPort)|\(remote)|\(port)"

        var flow: Flow
        if let existing = flows[key] {
            flow = existing
        } else {
            // 只在出现签名首包长度时才开始跟踪，免得给随机 UDP 流分配缓冲
            guard payloadLength == Self.handshakePrefix[0].length else {
                signatureFiltered += 1
                return []
            }
            if flows.count >= Self.maxTrackedFlows {
                evictIdle(now: now)
                guard flows.count < Self.maxTrackedFlows else {
                    signatureFiltered += 1
                    return []
                }
            }
            flow = Flow(lastSeen: now)
        }
        flow.lastSeen = now

        // ③ 已判定为对局流，之后全部直发
        if flow.game {
            flows[key] = flow
            return [packet]
        }

        if flow.matched < Self.handshakePrefix.count {
            let expected = Self.handshakePrefix[flow.matched]
            if expected.up == up, expected.length == payloadLength {
                flow.matched += 1
                flow.pending.append(packet)
                if flow.matched == Self.handshakePrefix.count {
                    flow.game = true
                    gameFlows += 1
                    let buffered = flow.pending
                    flow.pending = []
                    flows[key] = flow
                    onGame?("\(client):\(localPort) <-> \(remote):\(port)")
                    return buffered
                }
                flows[key] = flow
                return []
            }
        }

        // 乱序/重传容错：按有序子序列继续探测；缓冲超限即判定为非会话流并放弃
        flow.pending.append(packet)
        if flow.pending.count >= Self.handshakeProbeLimit {
            signatureFiltered += flow.pending.count
            flows.removeValue(forKey: key)
            return []
        }
        flows[key] = flow
        return []
    }

    /// 远端是不是内网/回环地址。域名解析不出网段，一律按公网放行。
    public static func isPrivate(_ host: String) -> Bool {
        if let raw = SOCKS5Address.ipv4Bytes(host) {
            switch (raw[0], raw[1]) {
            case (10, _), (172, 16...31), (192, 168), (169, 254), (127, _):
                return true
            default:
                return false
            }
        }
        guard let raw = SOCKS5Address.ipv6Bytes(host) else { return false }
        // fe80::/10 链路本地
        if raw[0] == 0xFE, raw[1] & 0xC0 == 0x80 { return true }
        // ::1
        return raw[15] == 1 && raw[0..<15].allSatisfy { $0 == 0 }
    }

    private func evictIdle(now: TimeInterval) {
        let cutoff = now - Self.flowIdleSeconds
        let dead = flows.filter { $0.value.lastSeen < cutoff }.map(\.key)
        for key in dead { flows.removeValue(forKey: key) }
    }
}
