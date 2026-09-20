import Foundation

/// 中间人引擎的运行参数
public struct EngineConfig {
    /// SOCKS5 监听端口。小火箭里填这个端口
    public var listenPort: UInt16
    /// UDP ASSOCIATE 回复给客户端的地址。nil 表示自动探测本机可达 IPv4。
    /// 自动探测不准时必须手工指定 —— 客户端拿到错地址就连不上 UDP 中继。
    public var advertisedHost: String?
    /// 需要做 DH 中间人的 TCP 目标端口。其余流量原样转发。
    /// 原实现抓的是 158。
    public var interceptPorts: Set<UInt16>
    /// UDP flow 空闲回收时间
    public var udpIdleTimeout: TimeInterval
    /// UDP flow 上限，超过就淘汰最久未活动的
    public var maxUDPFlows: Int

    public init(
        listenPort: UInt16 = 1080,
        advertisedHost: String? = nil,
        interceptPorts: Set<UInt16> = [158],
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
        update { $0.lastError = "\(error)" }
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
