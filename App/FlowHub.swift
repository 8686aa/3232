import Foundation

/// 运行期链路快照。
/// 引擎队列写入，界面每秒读一次：
///  · 内环客户端 = 连接本机代理的热点设备
///  · 外环远端   = 客户端实际访问的目标
///  · 待展示报文 = 限量缓存，界面每次限速取走一批，避免刷爆列表
///  · 上下行计数 = 星图/统计卡用的累计值
final class FlowHub {

    static let shared = FlowHub()

    private let maxPending = 400
    private let clientLinger: TimeInterval = 60      // 客户端离线后仍在星图上保留一会儿
    private let remoteLinger: TimeInterval = 8

    private let lock = NSLock()
    private var clients: [String: Date] = [:]
    private var remotes: [String: Date] = [:]
    private var pending: [PktInfo] = []
    private var upPackets: Int64 = 0
    private var downPackets: Int64 = 0
    private var upBytes: Int64 = 0
    private var downBytes: Int64 = 0

    private init() {}

    /// 每转发一段数据调用一次：登记链路两端、累计计数并把报文排进展示队列
    func report(up: Bool, srcIp: String, sport: Int, dstIp: String, dport: Int, len: Int) {
        lock.lock(); defer { lock.unlock() }
        let now = Date()
        clients[up ? srcIp : dstIp] = now
        remotes[up ? dstIp : srcIp] = now

        if up {
            upPackets += 1
            upBytes += Int64(len)
        } else {
            downPackets += 1
            downBytes += Int64(len)
        }

        if pending.count >= maxPending { pending.removeFirst() }
        pending.append(PktInfo(time: now,
                               up: up,
                               srcIp: srcIp,
                               srcPort: sport,
                               dstIp: dstIp,
                               dstPort: dport,
                               proto: "UDP",
                               len: len,
                               target: false))
    }

    /// 累计上下行（报文数 + 字节数）
    func totals() -> (upPackets: Int64, downPackets: Int64, upBytes: Int64, downBytes: Int64) {
        lock.lock(); defer { lock.unlock() }
        return (upPackets, downPackets, upBytes, downBytes)
    }

    func clientIps() -> [String] {
        lock.lock(); defer { lock.unlock() }
        let now = Date()
        let stale = clients.filter { now.timeIntervalSince($0.value) > clientLinger }.map { $0.key }
        for k in stale { clients.removeValue(forKey: k) }
        return clients.keys.sorted()
    }

    func remoteIps() -> [String] {
        lock.lock(); defer { lock.unlock() }
        let now = Date()
        let stale = remotes.filter { now.timeIntervalSince($0.value) > remoteLinger }.map { $0.key }
        for k in stale { remotes.removeValue(forKey: k) }
        return remotes.keys.sorted()
    }

    /// 取走最多 max 条待展示报文
    func drain(_ max: Int) -> [PktInfo] {
        lock.lock(); defer { lock.unlock() }
        let n = min(max, pending.count)
        guard n > 0 else { return [] }
        let out = Array(pending[0..<n])
        pending.removeFirst(n)
        return out
    }

    func clear() {
        lock.lock(); defer { lock.unlock() }
        clients.removeAll()
        remotes.removeAll()
        pending.removeAll()
        upPackets = 0
        downPackets = 0
        upBytes = 0
        downBytes = 0
    }
}
