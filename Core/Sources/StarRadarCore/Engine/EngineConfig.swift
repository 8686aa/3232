import Foundation
import Network

/// 中间人引擎的运行参数
public struct EngineConfig {
    /// SOCKS5 监听端口。小火箭里填这个端口
    public var listenPort: UInt16
    /// UDP ASSOCIATE 回复给客户端的地址。nil 表示自动探测本机可达 IPv4。
    /// 自动探测不准时必须手工指定 —— 客户端拿到错地址就连不上 UDP 中继。
    public var advertisedHost: String?
    /// 需要做 DH 中间人的 TCP 目标端口。其余流量原样转发。
    /// 真实游戏端口是 65010。原实现里的 158 是从服务器 IP `123.99.198.158`
    /// 的尾巴上误读出来的，按它拦永远拦不到东西。
    public var interceptPorts: Set<UInt16>
    /// UDP flow 空闲回收时间
    public var udpIdleTimeout: TimeInterval
    /// UDP flow 上限，超过就淘汰最久未活动的
    public var maxUDPFlows: Int

    public init(
        listenPort: UInt16 = 1080,
        advertisedHost: String? = nil,
        interceptPorts: Set<UInt16> = [65010],
        udpIdleTimeout: TimeInterval = 120,
        maxUDPFlows: Int = 256
    ) {
        self.listenPort = listenPort
        self.advertisedHost = advertisedHost
        self.interceptPorts = interceptPorts
        self.udpIdleTimeout = udpIdleTimeout
        self.maxUDPFlows = maxUDPFlows
    }
}

/// 引擎计数快照
public struct EngineStats: Equatable {
    public var connectAccepted = 0
    public var udpAssociateAccepted = 0
    public var relaySessions = 0
    public var middlemanSessions = 0
    public var clientHelloSeen = 0
    public var serverHelloSeen = 0
    public var translatedFrames = 0
    public var translateFailures = 0
    public var udpDatagramsToUpstream = 0
    public var udpDatagramsFromUpstream = 0
    public var udpFlows = 0
    public var cryptoCandidates = 0
    public var lastError: String?

    /// 显式给一个公开构造：App target 在另一个模块，拿不到合成的 internal 逐一构造器
    public init() {}
}

/// 把 `NWError` 翻成能直接照着做的说明。
///
/// 界面和日志里原本直接打 `"\(error)"`，得到的是 `POSIXErrorCode(rawValue: 60)`
/// 这种谁也看不懂的东西。下面这几个码恰好是排障时最先要认出来的：
/// 48 端口被占、60 超时无应答、61 被拒、65 无路由。
func describeNetworkError(_ error: Error) -> String {
    guard let nwError = error as? NWError, case .posix(let code) = nwError else {
        return "\(error)"
    }
    let name: String
    let hint: String
    switch code.rawValue {
    case 48:
        name = "EADDRINUSE"
        hint = "端口已被占用（小火箭本地代理默认也占 1080，换个监听端口）"
    case 50:
        name = "ENETDOWN"
        hint = "网络接口不可用（本机没网，或没给「本地网络」权限）"
    case 51:
        name = "ENETUNREACH"
        hint = "网络不可达（这个地址在本机没有路由）"
    case 54:
        name = "ECONNRESET"
        hint = "对端把连接重置了"
    case 57:
        name = "ENOTCONN"
        hint = "连接未建立"
    case 60:
        name = "ETIMEDOUT"
        hint = "超时且没有任何应答（SYN 被丢弃：目标不可达、被防火墙丢包，或本机出站又被 TUN 抓回去成了环）"
    case 61:
        name = "ECONNREFUSED"
        hint = "对端拒绝（目标端口没在监听）"
    case 64:
        name = "EHOSTDOWN"
        hint = "主机不在线"
    case 65:
        name = "EHOSTUNREACH"
        hint = "主机不可达（地址没有路由，小火箭 fake-ip 常见这个）"
    default:
        return "POSIX \(code.rawValue)：\(error)"
    }
    return "\(name)（POSIX \(code.rawValue)）：\(hint)"
}

/// 跨线程计数。网络回调在多个队列上跑，这里统一加锁。
final class StatsCounter {
    private let lock = NSLock()
    private var value = EngineStats()

    func update(_ body: (inout EngineStats) -> Void) {
        lock.lock()
        defer { lock.unlock() }
        body(&value)
    }

    func snapshot() -> EngineStats {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func record(error: Error) {
        update { $0.lastError = describeNetworkError(error) }
    }
}

/// 环形事件日志。界面只展示最近若干行，所以只留尾部。
public final class EventLog {
    public var onLine: ((String) -> Void)?

    private let lock = NSLock()
    private let capacity: Int
    private var lines: [String] = []
    private let formatter: DateFormatter

    public init(capacity: Int = 400) {
        self.capacity = capacity
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        self.formatter = formatter
    }

    public func write(_ message: String) {
        let line = "[\(formatter.string(from: Date()))] \(message)"
        lock.lock()
        lines.append(line)
        if lines.count > capacity {
            lines.removeFirst(lines.count - capacity)
        }
        lock.unlock()
        onLine?(line)
    }

    public func recent(_ count: Int) -> [String] {
        lock.lock()
        defer { lock.unlock() }
        guard count > 0 else { return [] }
        return Array(lines.suffix(count))
    }
}
