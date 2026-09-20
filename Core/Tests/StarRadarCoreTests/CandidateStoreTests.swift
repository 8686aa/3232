import XCTest
@testable import StarRadarCore

/// 期望值对齐 `pytho/_dis/key_material.dis.txt` 的字节码语义：
/// 房间/世代校验、插入序淘汰、`created <= clock() - ttl` 过期、`(session, fingerprint)` 去重。
final class CandidateStoreTests: XCTestCase {
    /// 可控单调时钟，替代原实现的 `time.monotonic`
    private final class FakeClock {
        var now: Double
        init(_ start: Double = 1000) { now = start }
        func read() -> Double { now }
    }

    private func material(_ seed: UInt8) -> [UInt8] {
        [UInt8](repeating: seed, count: 128)
    }

    private func candidate(
        session: String = "s1",
        material bytes: [UInt8]? = nil,
        command: Int = 16403,
        sequence: Int = 1
    ) -> KeyCandidate {
        KeyCandidate(
            session: session,
            upstream: .init(host: "10.0.0.1", port: 65010),
            command: command,
            sequence: sequence,
            layer: "plain",
            offset: 4,
            material: bytes ?? material(7),
            sourceContext: [1, 2, 3],
            contextStart: 2
        )
    }

    private func store(
        room: Int = 158,
        generation: String = "g1",
        maxCandidates: Int = CandidateStore.defaultMaxCandidates,
        ttl: Double = CandidateStore.defaultTTL,
        clock: @escaping () -> Double = { 1000 }
    ) throws -> CandidateStore {
        try CandidateStore(
            room: room,
            generation: generation,
            maxCandidates: maxCandidates,
            ttl: ttl,
            clock: clock
        )
    }

    // MARK: - 构造校验

    func testRejectsMissingRoomOrGeneration() {
        for room in [0, -1, 41] {
            XCTAssertThrowsError(try store(room: room)) { error in
                XCTAssertEqual(error as? CandidateStore.StoreError, .explicitRoomAndGenerationRequired)
            }
        }
        // 边界内的房间号合法
        XCTAssertNoThrow(try store(room: 1))
        XCTAssertNoThrow(try store(room: 40))

        XCTAssertThrowsError(try store(generation: "")) { error in
            XCTAssertEqual(error as? CandidateStore.StoreError, .explicitRoomAndGenerationRequired)
        }
    }

    func testRejectsInvalidLimits() {
        for maxCandidates in [0, 257] {
            XCTAssertThrowsError(try store(maxCandidates: maxCandidates)) { error in
                XCTAssertEqual(error as? CandidateStore.StoreError, .invalidLimits)
            }
        }
        for ttl in [0.0, 3600.1] {
            XCTAssertThrowsError(try store(ttl: ttl)) { error in
                XCTAssertEqual(error as? CandidateStore.StoreError, .invalidLimits)
            }
        }
        XCTAssertNoThrow(try store(maxCandidates: 1, ttl: 0.1))
        XCTAssertNoThrow(try store(maxCandidates: 256, ttl: 3600))
    }

    // MARK: - accept

    /// 房间/世代不匹配要**先于**材料校验返回 false，坏材料也不能抛出去
    func testWrongRoomOrGenerationReturnsFalseBeforeMaterialValidation() throws {
        let store = try store()
        let broken = candidate(material: [1, 2, 3])

        XCTAssertFalse(try store.accept(broken, room: 159, generation: "g1"))
        XCTAssertFalse(try store.accept(broken, room: 158, generation: "g2"))
        XCTAssertEqual(store.status().candidateCount, 0)
    }

    func testRejectsInvalidRawDHMaterial() throws {
        let store = try store()

        XCTAssertThrowsError(try store.accept(candidate(session: ""), room: 158, generation: "g1")) {
            XCTAssertEqual($0 as? CandidateStore.StoreError, .invalidRawDHCandidateMaterial)
        }
        for count in [0, 16, 127, 129] {
            let bytes = [UInt8](repeating: 9, count: count)
            XCTAssertThrowsError(try store.accept(candidate(material: bytes), room: 158, generation: "g1")) {
                XCTAssertEqual($0 as? CandidateStore.StoreError, .invalidRawDHCandidateMaterial)
            }
        }
        XCTAssertEqual(store.status().candidateCount, 0)
    }

    func testAcceptsAndDeduplicatesByIdentity() throws {
        let store = try store()

        XCTAssertTrue(try store.accept(candidate(), room: 158, generation: "g1"))
        // 同会话同材料：再去一次是重复
        XCTAssertFalse(try store.accept(candidate(), room: 158, generation: "g1"))
        // 同材料但不同会话：各算一条
        XCTAssertTrue(try store.accept(candidate(session: "s2"), room: 158, generation: "g1"))
        // 同会话但材料不同：也算一条
        XCTAssertTrue(try store.accept(candidate(material: material(8)), room: 158, generation: "g1"))

        XCTAssertEqual(store.status().candidateCount, 3)
        XCTAssertEqual(store.forSession("s1", room: 158, generation: "g1").count, 2)
        XCTAssertEqual(store.forSession("s2", room: 158, generation: "g1").count, 1)
    }

    /// 超限淘汰的是**最早进来**的那条，不是按创建时间
    func testEvictsOldestInsertedWhenOverCapacity() throws {
        let clock = FakeClock()
        let store = try store(maxCandidates: 2, clock: clock.read)

        XCTAssertTrue(try store.accept(candidate(session: "s1"), room: 158, generation: "g1"))
        clock.now += 10
        XCTAssertTrue(try store.accept(candidate(session: "s2"), room: 158, generation: "g1"))
        clock.now += 10
        XCTAssertTrue(try store.accept(candidate(session: "s3"), room: 158, generation: "g1"))

        XCTAssertEqual(store.status().candidateCount, 2)
        XCTAssertTrue(store.forSession("s1", room: 158, generation: "g1").isEmpty)
        XCTAssertEqual(store.forSession("s2", room: 158, generation: "g1").count, 1)
        XCTAssertEqual(store.forSession("s3", room: 158, generation: "g1").count, 1)
    }

    // MARK: - 过期与关闭

    /// 过期判定是 `created <= clock() - ttl`，卡在 ttl 整点上同样算过期
    func testPrunesEntriesAtOrPastTTL() throws {
        let clock = FakeClock(1000)
        let store = try store(ttl: 10, clock: clock.read)

        XCTAssertTrue(try store.accept(candidate(session: "s1"), room: 158, generation: "g1"))
        clock.now = 1005
        XCTAssertTrue(try store.accept(candidate(session: "s2"), room: 158, generation: "g1"))

        XCTAssertEqual(store.status().candidateCount, 2)
        clock.now = 1010
        // 第一条 created=1000 <= deadline=1000 过期，第二条 created=1005 还在
        XCTAssertEqual(store.status().candidateCount, 1)
        XCTAssertTrue(store.forSession("s1", room: 158, generation: "g1").isEmpty)
        XCTAssertEqual(store.forSession("s2", room: 158, generation: "g1").count, 1)

        clock.now = 1020
        XCTAssertEqual(store.status().candidateCount, 0)
    }

    func testForSessionHonoursRoomAndGeneration() throws {
        let store = try store()
        XCTAssertTrue(try store.accept(candidate(), room: 158, generation: "g1"))

        XCTAssertTrue(store.forSession("s1", room: 159, generation: "g1").isEmpty)
        XCTAssertTrue(store.forSession("s1", room: 158, generation: "g2").isEmpty)
        XCTAssertTrue(store.forSession("other", room: 158, generation: "g1").isEmpty)
    }

    func testCloseDropsEntriesAndRefusesAccepts() throws {
        let store = try store()
        XCTAssertTrue(try store.accept(candidate(), room: 158, generation: "g1"))

        store.close()

        XCTAssertFalse(try store.accept(candidate(session: "s2"), room: 158, generation: "g1"))
        XCTAssertTrue(store.forSession("s1", room: 158, generation: "g1").isEmpty)
        let status = store.status()
        XCTAssertEqual(status.candidateCount, 0)
        XCTAssertTrue(status.closed)
    }

    // MARK: - status

    func testStatusNeverClaimsVerifiedKeys() throws {
        let store = try store()
        XCTAssertTrue(try store.accept(candidate(), room: 158, generation: "g1"))

        let status = store.status()
        XCTAssertEqual(status.room, 158)
        XCTAssertEqual(status.generation, "g1")
        XCTAssertEqual(status.candidateCount, 1)
        // 候选池永远不宣称「已验证」，验证是下游的事
        XCTAssertEqual(status.verifiedUDPKeyCount, 0)
        XCTAssertFalse(status.closed)
    }

    /// 指纹就是材料的 sha256；这个值与 login_materials 抽同一条材料时一致
    func testFingerprintMatchesSHA256OfMaterial() {
        let bytes = (0..<128).map { UInt8($0) }
        let candidate = candidate(material: bytes)
        XCTAssertEqual(
            candidate.fingerprint,
            "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5"
        )
        XCTAssertEqual(candidate.material.count, 128)
    }
}
