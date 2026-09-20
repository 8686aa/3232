import Foundation

/// 一条待上送的 IP 报文，逐字段对应原实现 `ws.go` 的 `pendingItem`。
public struct UploadPacket: Equatable {
    /// 入队序号，全局单调递增。出队时按它做精确前缀删除
    public let sequence: UInt64
    /// 连接代次：入队时所在连接的编号。重连后 `generation < 当前代次` 即断线期间积压
    public let generation: UInt64
    /// 入队时生效的密钥版本（sha256 前 16 位），随包上报，转发器据此匹配密钥
    public let keyID: String?
    /// 入队时间（单调秒）。补包窗口判定的预留字段，当前排空路径不用
    public let enqueuedAt: TimeInterval
    /// 完整 IP 数据报（已去以太网头、裁掉填充）
    public let datagram: [UInt8]

    public init(
        sequence: UInt64,
        generation: UInt64,
        keyID: String?,
        enqueuedAt: TimeInterval,
        datagram: [UInt8]
    ) {
        self.sequence = sequence
        self.generation = generation
        self.keyID = keyID
        self.enqueuedAt = enqueuedAt
        self.datagram = datagram
    }
}

/// 上报队列：**发送成功才出队**。
///
/// 队里任何时刻都只有「尚未确认送达」的报文，因此写失败时什么都不用做 ——
/// 整批留队、断开重连，重连后自然从最旧的补起。三个必须原样保留的细节：
///
/// - 超限时丢的是**队首最旧**的一条，不阻塞入队方（抓包线程）；
/// - 出队按 `seq` 精确前缀删除：即使期间发生过溢出丢弃，也不会误删后面的包；
/// - `seq` 与 `generation` 都在入队时固定下来，重连后旧包仍带旧代次与旧密钥版本。
public struct UploadQueue {
    /// 队列上限（原实现 `wsQueueLimit`）
    public static let defaultLimit = 20000
    /// 单批最大报文数（原实现 `wsBatchMax`）
    public static let defaultBatchMax = 40

    public let limit: Int
    /// 因溢出丢弃的条数
    public private(set) var dropped = 0

    private var packets: [UploadPacket] = []
    private var nextSequence: UInt64 = 0

    public init(limit: Int = defaultLimit) {
        self.limit = max(1, limit)
    }

    public var count: Int { packets.count }
    public var isEmpty: Bool { packets.isEmpty }

    /// 入队。空报文直接忽略；满员时先丢最旧的一条再入队。
    @discardableResult
    public mutating func enqueue(
        _ datagram: [UInt8],
        generation: UInt64,
        keyID: String?,
        now: TimeInterval
    ) -> UploadPacket? {
        guard !datagram.isEmpty else { return nil }
        nextSequence += 1
        while packets.count >= limit {
            packets.removeFirst()
            dropped += 1
        }
        let packet = UploadPacket(
            sequence: nextSequence,
            generation: generation,
            keyID: keyID,
            enqueuedAt: now,
            datagram: datagram
        )
        packets.append(packet)
        return packet
    }

    /// 取队首一批**不出队** —— 只有写成功之后才删。
    public func peekBatch(max: Int = defaultBatchMax) -> [UploadPacket] {
        guard max > 0 else { return [] }
        return Array(packets.prefix(max))
    }

    /// 出队：删掉队首所有 `seq <= sequence` 的包，返回被删掉的那些（调用方据此数补包）。
    ///
    /// 用上界比较而不是「删前 n 条」：取批与写完成之间可能又发生过溢出丢包，
    /// 按条数删会把没发出去的包一起删掉，按 `seq` 删则天然只影响已确认送达的部分。
    @discardableResult
    public mutating func dropPrefix(through sequence: UInt64) -> [UploadPacket] {
        var removed: [UploadPacket] = []
        while let first = packets.first, first.sequence <= sequence {
            removed.append(packets.removeFirst())
        }
        return removed
    }

    /// 当前待补发积压：队首连续 `generation < 当前代次` 的条数。
    ///
    /// 队列按入队顺序排列，代次单调不减，所以「第一条第 >= 当前代次」之前的
    /// 所有元素就是跨连接遗留下来的包。
    public func replayBacklog(generation: UInt64) -> Int {
        var backlog = 0
        for packet in packets {
            if packet.generation >= generation { break }
            backlog += 1
        }
        return backlog
    }

    public mutating func removeAll() {
        packets.removeAll()
    }
}
