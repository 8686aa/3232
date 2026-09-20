import CryptoKit
import Foundation

/// 一个 `(host, port)` 对。对应原实现里到处出现的 `tuple[str, int]`
/// —— 候选的上游、证据记录里的 upstream / udp_targets 都是这个形状。
public struct Endpoint: Equatable, Hashable {
    public let host: String
    public let port: Int

    public init(host: String, port: Int) {
        self.host = host
        self.port = port
    }
}

/// 一条明文里捞出来的候选密钥，带上它是在哪条会话、哪条指令的哪个偏移被看到的。
///
/// 注意语义：**候选不等于可用**。原实现的 CandidateStore 特意不声明算法，
/// 必须由下游用真实 UDP 战斗包验证通过后才能真正拿来解密。
public struct KeyCandidate: Equatable {
    /// 会话标识，用作候选归属的第一维
    public let session: String
    /// 上游地址（对应原实现的 `upstream: tuple[str, int]`）
    public let upstream: Endpoint
    /// TGCP 指令号
    public let command: Int
    /// 该指令在会话里的序号
    public let sequence: Int
    /// 命中所在的层次名（原文 / lz4）
    public let layer: String
    /// 命中处在层次里的字节偏移
    public let offset: Int
    /// 128 字节候选材料
    public let material: [UInt8]
    /// 命中处周围的原文，供下游判断这 128 字节属于哪个字段
    public let sourceContext: [UInt8]
    /// `sourceContext` 在层次内的起始偏移
    public let contextStart: Int

    public init(
        session: String,
        upstream: Endpoint,
        command: Int,
        sequence: Int,
        layer: String,
        offset: Int,
        material: [UInt8],
        sourceContext: [UInt8] = [],
        contextStart: Int = 0
    ) {
        self.session = session
        self.upstream = upstream
        self.command = command
        self.sequence = sequence
        self.layer = layer
        self.offset = offset
        self.material = material
        self.sourceContext = sourceContext
        self.contextStart = contextStart
    }

    /// 材料指纹。日志与状态里只允许出现它，**不允许出现原文材料**。
    public var fingerprint: String {
        ByteCoding.hex(Array(SHA256.hash(data: Data(material))))
    }
}

/// 一个房间世代内的候选密钥池。
///
/// 三条硬约束，缺一条都会让候选串味：
/// 1. `room` 与 `generation` 必须显式给出且完全匹配，否则一律拒收；
/// 2. 同一 `(session, fingerprint)` 只收一次，不同会话的同材料各算一条；
/// 3. 超过 `maxCandidates` 先淘汰**最早进来**的那条（按插入序，不是按创建时间）。
///
/// 另外这个池子**不保证**任何算法 —— 验证是下游的事。
public final class CandidateStore {
    public enum StoreError: Error, Equatable {
        case explicitRoomAndGenerationRequired
        case invalidLimits
        case invalidRawDHCandidateMaterial
    }

    /// 原实现的默认值
    public static let defaultMaxCandidates = 64
    public static let defaultTTL: Double = 900

    public let room: Int
    public let generation: String
    public let maxCandidates: Int
    public let ttl: Double

    private let clock: () -> Double
    /// 插入序，用来复刻 Python dict 的 `next(iter(_entries))` —— 淘汰最旧的
    private var order: [Identity] = []
    private var entries: [Identity: (created: Double, candidate: KeyCandidate)] = [:]
    private var closed = false

    private struct Identity: Hashable {
        let session: String
        let fingerprint: String
    }

    /// - Parameters:
    ///   - clock: 单调时钟。默认 `systemUptime`，与原实现的 `time.monotonic` 同语义。
    public init(
        room: Int,
        generation: String,
        maxCandidates: Int = CandidateStore.defaultMaxCandidates,
        ttl: Double = CandidateStore.defaultTTL,
        clock: @escaping () -> Double = { ProcessInfo.processInfo.systemUptime }
    ) throws {
        guard (1...40).contains(room), !generation.isEmpty else {
            throw StoreError.explicitRoomAndGenerationRequired
        }
        guard (1...256).contains(maxCandidates), ttl > 0, ttl <= 3600 else {
            throw StoreError.invalidLimits
        }
        self.room = room
        self.generation = generation
        self.maxCandidates = maxCandidates
        self.ttl = ttl
        self.clock = clock
    }

    // MARK: - 收候选

    /// 收下一条候选。
    ///
    /// 顺序很关键：**房间/世代不匹配要早于材料校验**返回 `false`，
    /// 否则拿错房间的坏材料会抛异常而不是被静默丢弃。
    /// - Returns: 真正入库返回 `true`；重复、已关闭或房间/世代不匹配返回 `false`。
    @discardableResult
    public func accept(_ candidate: KeyCandidate, room: Int, generation: String) throws -> Bool {
        if closed || room != self.room || generation != self.generation { return false }
        guard !candidate.session.isEmpty, candidate.material.count == 128 else {
            throw StoreError.invalidRawDHCandidateMaterial
        }

        prune()

        let identity = Identity(session: candidate.session, fingerprint: candidate.fingerprint)
        if entries[identity] != nil { return false }
        while entries.count >= maxCandidates, let oldest = order.first {
            order.removeFirst()
            entries.removeValue(forKey: oldest)
        }
        entries[identity] = (clock(), candidate)
        order.append(identity)
        return true
    }

    /// 取某个会话名下的候选，按入库顺序返回。
    public func forSession(_ session: String, room: Int, generation: String) -> [KeyCandidate] {
        if closed || room != self.room || generation != self.generation { return [] }
        prune()
        return order.compactMap { entries[$0]?.candidate }.filter { $0.session == session }
    }

    // MARK: - 观测与关闭

    public struct Status: Equatable {
        public let room: Int
        public let generation: String
        public let candidateCount: Int
        /// 恒为 0：本池子从不宣称任何候选已经验证通过
        public let verifiedUDPKeyCount: Int
        public let closed: Bool
    }

    public func status() -> Status {
        prune()
        return Status(
            room: room,
            generation: generation,
            candidateCount: entries.count,
            verifiedUDPKeyCount: 0,
            closed: closed
        )
    }

    public func close() {
        entries.removeAll()
        order.removeAll()
        closed = true
    }

    // MARK: - 过期清理

    private func prune() {
        let deadline = clock() - ttl
        var expired = false
        for identity in order {
            guard let entry = entries[identity], entry.created <= deadline else { continue }
            entries.removeValue(forKey: identity)
            expired = true
        }
        if expired {
            order.removeAll { entries[$0] == nil }
        }
    }
}
