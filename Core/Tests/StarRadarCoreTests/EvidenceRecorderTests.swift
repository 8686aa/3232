import CryptoKit
import XCTest
@testable import StarRadarCore

/// 语义对齐 `pytho/_dis/key_evidence.dis.txt`：
/// `HM158DP1` 候选 / `HM158MT1` 材料 / 64 条上限 / 幂等 / `.tmp` 再改名 / PCAP 有界。
/// DPAPI 在 iOS 侧换成钥匙串主密钥 + AES-256-GCM，所以测试注入固定主密钥，
/// 不去碰真机钥匙串（CI 上是无头 runner，钥匙串不可用）。
final class EvidenceRecorderTests: XCTestCase {
    private var root: URL!
    private let masterKey = Data(repeating: 0x5A, count: 32)

    /// PCAP 全局头的逐字节黄金向量
    private let pcapHeader: [UInt8] = [
        0xD4, 0xC3, 0xB2, 0xA1,   // magic = 0xA1B2C3D4，小端
        0x02, 0x00,               // version_major = 2
        0x04, 0x00,               // version_minor = 4
        0x00, 0x00, 0x00, 0x00,   // thiszone
        0x00, 0x00, 0x00, 0x00,   // sigfigs
        0xFF, 0xFF, 0x00, 0x00,   // snaplen = 65535
        0x65, 0x00, 0x00, 0x00,   // network = 101 (LINKTYPE_RAW)
    ]

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("evidence-\(UUID().uuidString)")
    }

    override func tearDownWithError() throws {
        if let root, FileManager.default.fileExists(atPath: root.path) {
            try FileManager.default.removeItem(at: root)
        }
    }

    private func makeRecorder(
        room: Int = 7,
        maxBytes: Int = EvidenceRecorder.defaultMaxBytes,
        server: String = "123.99.198.158"
    ) throws -> EvidenceRecorder {
        try EvidenceRecorder(
            root: root,
            room: room,
            maxBytes: maxBytes,
            server: server,
            protector: try EvidenceProtector(masterKeyData: masterKey)
        )
    }

    private func makeProtector() throws -> EvidenceProtector {
        try EvidenceProtector(masterKeyData: masterKey)
    }

    private func digest(_ text: String) -> String {
        Hex.encode(SHA256.hash(data: Data(text.utf8)))
    }

    private func candidate(
        session: String = "s1",
        material: [UInt8] = [UInt8](repeating: 0x11, count: 128),
        context: [UInt8] = [1, 2, 3],
        contextStart: Int = 2
    ) -> KeyCandidate {
        KeyCandidate(
            session: session,
            upstream: Endpoint(host: "10.0.0.9", port: 65010),
            command: 16403,
            sequence: 7,
            layer: "plain",
            offset: 256,
            material: material,
            sourceContext: context,
            contextStart: contextStart
        )
    }

    private func json(_ url: URL) throws -> [String: Any] {
        let object = try JSONSerialization.jsonObject(with: try Data(contentsOf: url))
        return try XCTUnwrap(object as? [String: Any])
    }

    private func readUInt32LE(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    // MARK: - 构造校验

    func testRejectsInvalidLimitsRoomAndServer() throws {
        for room in [0, 41] {
            XCTAssertThrowsError(try makeRecorder(room: room)) {
                XCTAssertEqual($0 as? EvidenceError, .invalidLimitsOrRoom)
            }
        }
        XCTAssertThrowsError(try makeRecorder(maxBytes: 23)) {
            XCTAssertEqual($0 as? EvidenceError, .invalidLimitsOrRoom)
        }
        // 对应 str(IPv4Address(server))：非 IPv4 一律拒绝
        for server in ["", "not-an-ip", "1.2.3.4.5", "::1"] {
            XCTAssertThrowsError(try makeRecorder(server: server)) {
                XCTAssertEqual($0 as? EvidenceError, .invalidServerAddress)
            }
        }
        XCTAssertNoThrow(try makeRecorder(maxBytes: 24))
    }

    /// 原实现用 open('xb')：同一目录不能录第二遍
    func testSecondRecorderOnSameRootFails() throws {
        _ = try makeRecorder()
        XCTAssertThrowsError(try makeRecorder()) {
            XCTAssertEqual($0 as? EvidenceError, .existingRecording)
        }
    }

    // MARK: - 候选记录

    func testCandidateRecordRoundTripsThroughMagicAndProtection() throws {
        let recorder = try makeRecorder()
        let candidate = candidate()
        XCTAssertTrue(try recorder.record(candidate))

        let identity = digest("s1:\(candidate.fingerprint)")
        let url = root.appendingPathComponent("candidate-\(identity).dpapi")
        let raw = [UInt8](try Data(contentsOf: url))
        // 8 字节 magic 后面直接跟保护后的数据，且不能用明文认出材料
        XCTAssertEqual(Array(raw.prefix(8)), Array(EvidenceRecorder.candidateMagic.utf8))
        XCTAssertFalse(raw.contains(0x11))

        let evidence = try EvidenceRecorder.readCandidate(at: url, protector: try makeProtector())
        XCTAssertEqual(evidence.schema, 1)
        XCTAssertEqual(evidence.server, "123.99.198.158")
        XCTAssertEqual(evidence.room, 7)
        XCTAssertEqual(evidence.generation.count, 32)
        XCTAssertEqual(evidence.session, "s1")
        XCTAssertEqual(evidence.upstream, Endpoint(host: "10.0.0.9", port: 65010))
        XCTAssertEqual(evidence.command, 16403)
        XCTAssertEqual(evidence.sequence, 7)
        XCTAssertEqual(evidence.layer, "plain")
        XCTAssertEqual(evidence.offset, 256)
        XCTAssertEqual(evidence.material, candidate.material)
        XCTAssertEqual(evidence.sha256, candidate.fingerprint)
        XCTAssertEqual(evidence.sourceContext, [1, 2, 3])
        XCTAssertEqual(evidence.contextStart, 2)
        // 证据里永远不许出现「已验证」
        XCTAssertFalse(evidence.verifiedUDPKey)
    }

    /// 重复记录返回 true 且不再落第二份文件
    func testDuplicateCandidateIsIdempotent() throws {
        let recorder = try makeRecorder()
        XCTAssertTrue(try recorder.record(candidate()))
        XCTAssertTrue(try recorder.record(candidate()))

        let files = try FileManager.default.contentsOfDirectory(atPath: root.path)
        XCTAssertEqual(files.filter { $0.hasPrefix(EvidenceRecorder.candidatePrefix) }.count, 1)
    }

    /// 只有非空上下文才校验长度与起点
    func testContextBoundsOnlyApplyWhenPresent() throws {
        let recorder = try makeRecorder()
        let tooLong = [UInt8](repeating: 0, count: EvidenceRecorder.maxContextBytes + 1)
        XCTAssertThrowsError(try recorder.record(candidate(context: tooLong, contextStart: 0))) {
            XCTAssertEqual($0 as? EvidenceError, .invalidProtectedSourceContext)
        }
        XCTAssertThrowsError(try recorder.record(candidate(contextStart: -1))) {
            XCTAssertEqual($0 as? EvidenceError, .invalidProtectedSourceContext)
        }
        // 空上下文直接跳过校验
        XCTAssertTrue(try recorder.record(candidate(material: [UInt8](repeating: 0x22, count: 128), context: [])))
    }

    func testRecordLimitIsSixtyFour() throws {
        let recorder = try makeRecorder()
        for index in 0..<EvidenceRecorder.maxRecords {
            var material = [UInt8](repeating: 0, count: 128)
            material[0] = UInt8(index)
            XCTAssertTrue(try recorder.record(candidate(material: material, context: [])))
        }
        // 第 65 条超限，返回 false 但不抛
        var overflow = [UInt8](repeating: 0, count: 128)
        overflow[1] = 0xFF
        XCTAssertFalse(try recorder.record(candidate(material: overflow, context: [])))

        try recorder.close()
        let summary = try json(root.appendingPathComponent("summary.json"))
        XCTAssertEqual(summary["candidate_count"] as? Int, EvidenceRecorder.maxRecords)
    }

    // MARK: - 材料记录

    func testMaterialRecordUsesItsOwnMagic() throws {
        let recorder = try makeRecorder()
        let payload = [UInt8](repeating: 0x33, count: 128)
        let material = EvidenceMaterial(
            session: "s3",
            upstream: Endpoint(host: "10.0.0.9", port: 65010),
            command: 16403,
            sequence: 12,
            kind: .namedKeyCandidate,
            fieldPath: "$.data.encryptionKey",
            payload: payload,
            udpTargets: [Endpoint(host: "1.2.3.4", port: 65010)]
        )
        XCTAssertTrue(try recorder.recordMaterial(material))

        let identity = digest("s3:\(material.kind.rawValue):\(material.fingerprint)")
        let url = root.appendingPathComponent("material-\(identity).dpapi")
        let raw = [UInt8](try Data(contentsOf: url))
        XCTAssertEqual(Array(raw.prefix(8)), Array(EvidenceRecorder.materialMagic.utf8))

        let plain = try (try makeProtector()).unprotect(Array(raw.dropFirst(8)))
        let row = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(plain)) as? [String: Any]
        )
        XCTAssertEqual(row["kind"] as? String, "named-key-candidate")
        XCTAssertEqual(row["field_path"] as? String, "$.data.encryptionKey")
        XCTAssertEqual((row["udp_targets"] as? [[Any]])?.count, 1)
        XCTAssertEqual(row["payload_b64"] as? String, Data(payload).base64EncodedString())
        XCTAssertEqual(row["verified_udp_key"] as? Bool, false)
    }

    func testMaterialPayloadBounds() throws {
        let recorder = try makeRecorder()
        func material(_ count: Int) -> EvidenceMaterial {
            EvidenceMaterial(
                session: "s3",
                upstream: Endpoint(host: "10.0.0.9", port: 65010),
                command: 16403,
                sequence: 12,
                kind: .udpAccessParameters,
                fieldPath: "$.accessInfo.json",
                payload: [UInt8](repeating: 1, count: count)
            )
        }
        XCTAssertThrowsError(try recorder.recordMaterial(material(0))) {
            XCTAssertEqual($0 as? EvidenceError, .materialOutOfBounds)
        }
        XCTAssertThrowsError(try recorder.recordMaterial(material(EvidenceRecorder.maxMaterialBytes + 1))) {
            XCTAssertEqual($0 as? EvidenceError, .materialOutOfBounds)
        }
        XCTAssertTrue(try recorder.recordMaterial(material(1)))
        XCTAssertTrue(try recorder.recordMaterial(material(EvidenceRecorder.maxMaterialBytes)))
        // 重复的仍然幂等
        XCTAssertTrue(try recorder.recordMaterial(material(1)))
    }

    // MARK: - PCAP

    func testPCAPHeaderAndPacketRecord() throws {
        let recorder = try makeRecorder()
        let packet = [UInt8](repeating: 0x45, count: 20)
        try recorder.writeUDP(timestampMicros: 1_700_000_000_123_456, packet: packet)

        XCTAssertEqual(recorder.packets, 1)
        XCTAssertEqual(recorder.size, 24 + 16 + 20)
        XCTAssertEqual(recorder.overLimit, 0)

        let data = [UInt8](try Data(contentsOf: root.appendingPathComponent("udp.pcap")))
        XCTAssertEqual(Array(data.prefix(24)), pcapHeader)
        XCTAssertEqual(readUInt32LE(data, 24), 1_700_000_000)
        XCTAssertEqual(readUInt32LE(data, 28), 123_456)
        XCTAssertEqual(readUInt32LE(data, 32), 20)
        XCTAssertEqual(readUInt32LE(data, 36), 20)
        XCTAssertEqual(Array(data[40...]), packet)
    }

    func testUDPRecordValidation() throws {
        let recorder = try makeRecorder()
        let packet = [UInt8](repeating: 0x45, count: 20)

        XCTAssertThrowsError(try recorder.writeUDP(timestampMicros: -1, packet: packet)) {
            XCTAssertEqual($0 as? EvidenceError, .invalidPCAPRecord)
        }
        XCTAssertThrowsError(
            try recorder.writeUDP(timestampMicros: 4_294_967_296_000_000, packet: packet)
        ) {
            XCTAssertEqual($0 as? EvidenceError, .invalidPCAPRecord)
        }
        for count in [0, 19, 65536] {
            XCTAssertThrowsError(
                try recorder.writeUDP(
                    timestampMicros: 1,
                    packet: [UInt8](repeating: 0, count: count)
                )
            ) {
                XCTAssertEqual($0 as? EvidenceError, .invalidPCAPRecord)
            }
        }
        XCTAssertEqual(recorder.packets, 0)
    }

    /// 超限只累加计数，不抛异常，也不再写文件
    func testUDPOverLimitIsCountedNotThrown() throws {
        let packet = [UInt8](repeating: 0x45, count: 20)
        let recorder = try makeRecorder(maxBytes: 24 + 16 + 20)
        try recorder.writeUDP(timestampMicros: 1, packet: packet)
        try recorder.writeUDP(timestampMicros: 2, packet: packet)

        XCTAssertEqual(recorder.packets, 1)
        XCTAssertEqual(recorder.overLimit, 1)
        XCTAssertEqual(recorder.size, 60)

        let data = [UInt8](try Data(contentsOf: root.appendingPathComponent("udp.pcap")))
        XCTAssertEqual(data.count, 60)
    }

    // MARK: - 汇总与读回防篡改

    func testSummaryReportAndDecoderStatus() throws {
        let recorder = try makeRecorder()
        XCTAssertTrue(try recorder.record(candidate()))
        try recorder.writeUDP(timestampMicros: 1, packet: [UInt8](repeating: 0x45, count: 20))
        try recorder.recordDecoderStatus(["stage": "handshake", "installed": 0])
        try recorder.close(captureDrops: 3)

        let summary = try json(root.appendingPathComponent("summary.json"))
        XCTAssertEqual(summary["room"] as? Int, 7)
        XCTAssertEqual(summary["server"] as? String, "123.99.198.158")
        XCTAssertEqual(summary["candidate_count"] as? Int, 1)
        XCTAssertEqual(summary["udp_packets"] as? Int, 1)
        XCTAssertEqual(summary["structured_material_count"] as? Int, 0)
        XCTAssertEqual(summary["pcap_bytes"] as? Int, 60)
        XCTAssertEqual(summary["capture_queue_drops"] as? Int, 3)
        XCTAssertEqual(summary["file_limit_drops"] as? Int, 0)
        XCTAssertEqual(summary["verified_udp_keys"] as? Int, 0)
        XCTAssertNotNil(summary["protection"] as? String)
        XCTAssertNotNil(summary["started_ms"] as? Int)
        XCTAssertNotNil(summary["ended_ms"] as? Int)

        let status = try json(root.appendingPathComponent("decoder-status.json"))
        XCTAssertEqual(status["stage"] as? String, "handshake")
    }

    func testReadCandidateRejectsBadFormatAndTamperedMaterial() throws {
        let protector = try makeProtector()

        // magic 不对
        let bad = root.appendingPathComponent("bad.dpapi")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try Data([0x00, 0x01, 0x02]).write(to: bad)
        XCTAssertThrowsError(try EvidenceRecorder.readCandidate(at: bad, protector: protector)) {
            XCTAssertEqual($0 as? EvidenceError, .invalidProtectedFormat)
        }

        // 超长文件
        let long = root.appendingPathComponent("long.dpapi")
        var oversized = Array(EvidenceRecorder.candidateMagic.utf8)
        oversized += [UInt8](repeating: 0, count: EvidenceRecorder.readLimit)
        try Data(oversized).write(to: long)
        XCTAssertThrowsError(try EvidenceRecorder.readCandidate(at: long, protector: protector)) {
            XCTAssertEqual($0 as? EvidenceError, .invalidProtectedFormat)
        }

        // 材料被换掉但 sha256 没跟着改
        let material = [UInt8](repeating: 0x11, count: 128)
        let row: [String: Any] = [
            "schema": 1,
            "material_b64": Data([UInt8](repeating: 0x22, count: 128)).base64EncodedString(),
            "sha256": Hex.encode(SHA256.hash(data: Data(material))),
        ]
        let tampered = root.appendingPathComponent("tampered.dpapi")
        let body = try protector.protect([UInt8](try JSONSerialization.data(withJSONObject: row)))
        try Data(Array(EvidenceRecorder.candidateMagic.utf8) + body).write(to: tampered)
        XCTAssertThrowsError(try EvidenceRecorder.readCandidate(at: tampered, protector: protector)) {
            XCTAssertEqual($0 as? EvidenceError, .invalidCandidateEvidence)
        }
    }

    // MARK: - 保护层

    func testProtectorRejectsWrongKeyAndWrongLength() throws {
        let protector = try makeProtector()
        let sealed = try protector.protect([1, 2, 3])
        XCTAssertEqual(try protector.unprotect(sealed), [1, 2, 3])

        // 换一把主密钥：GCM 的 tag 校验必须挡住
        let other = try EvidenceProtector(masterKeyData: Data(repeating: 0x7F, count: 32))
        XCTAssertThrowsError(try other.unprotect(sealed)) {
            XCTAssertEqual($0 as? EvidenceError, .invalidProtectedFormat)
        }
        // 密文被改一个字节
        var broken = sealed
        broken[broken.count - 1] ^= 0x01
        XCTAssertThrowsError(try protector.unprotect(broken))

        XCTAssertThrowsError(try EvidenceProtector(masterKeyData: Data(repeating: 0, count: 31))) {
            XCTAssertEqual($0 as? EvidenceError, .invalidMasterKeyLength)
        }
    }

    /// 自检失败必须挡在构造阶段（对应原实现的 protection self-check）
    func testRecorderRefusesToStartWhenProtectionFails() throws {
        let recorder = try makeRecorder()
        // 用另一把主密钥去读，等同于「解不开自己刚封的数据」
        XCTAssertEqual(recorder.room, 7)
        let wrong = try EvidenceProtector(masterKeyData: Data(repeating: 0x01, count: 32))
        let url = root.appendingPathComponent("udp.pcap")
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        let sealed = try wrong.protect([9, 9, 9])
        XCTAssertThrowsError(try wrong.unprotect(sealed + [0]))
    }
}
