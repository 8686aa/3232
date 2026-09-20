import XCTest
@testable import StarRadarCore

/// 上报侧的两块纯逻辑：闸门判定（②私网过滤 + ③握手签名门）与 IPv4 数据报组装。
/// 两者都不碰 socket，正好脱离真机直接对着规范验。
final class UploadGateTests: XCTestCase {
    private let client = "192.0.2.10"
    private let remote = "203.0.113.7"
    private let clientPort: UInt16 = 40000
    private let remotePort: UInt16 = 65010

    // MARK: - 造包

    /// 按方向造包：上行源是客户端，下行源是远端 —— 闸门要靠这个算出同一条流键。
    private func makePacket(length: Int, up: Bool, port: UInt16 = 65010) -> UDPPacket {
        let payload = [UInt8](repeating: 0xAB, count: length)
        if up {
            return UDPPacket(
                src: client, dst: remote, sport: clientPort, dport: port, payload: payload
            )
        }
        return UDPPacket(
            src: remote, dst: client, sport: port, dport: clientPort, payload: payload
        )
    }

    // MARK: - ③ 握手签名门

    func testIdentifiesGameFlowAndReplaysBufferedPackets() {
        let gate = UploadGate()
        var identified: [String] = []
        gate.onGame = { identified.append($0) }

        var emitted: [UDPPacket] = []
        for (index, item) in UploadGate.handshakePrefix.enumerated() {
            let out = gate.feed(makePacket(length: item.length, up: item.up), up: item.up)
            if index < UploadGate.handshakePrefix.count - 1 {
                XCTAssertTrue(out.isEmpty, "签名第 \(index + 1) 项还没凑齐，不该有输出")
            } else {
                emitted = out
            }
        }

        // 凑齐那一刻把缓冲的整段按到达顺序补发，握手阶段的包一个不少
        XCTAssertEqual(emitted.count, UploadGate.handshakePrefix.count)
        XCTAssertEqual(emitted.map { $0.payload.count }, UploadGate.handshakePrefix.map { $0.length })
        XCTAssertEqual(gate.gameFlows, 1)
        XCTAssertEqual(identified, ["\(client):\(clientPort) <-> \(remote):\(remotePort)"])
    }

    func testPassesEverythingThroughAfterIdentification() {
        let gate = UploadGate()
        for item in UploadGate.handshakePrefix {
            _ = gate.feed(makePacket(length: item.length, up: item.up), up: item.up)
        }

        // 长度不再是签名里的任何一项，照样直发
        let out = gate.feed(makePacket(length: 999, up: true), up: true)
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out.first?.payload.count, 999)
        XCTAssertEqual(gate.signatureFiltered, 0)
    }

    func testOutOfOrderPacketRidesAlongInArrivalOrder() {
        let gate = UploadGate()

        // 签名第 1 项之后插一条无关长度的包：进缓冲，但不推进签名
        XCTAssertTrue(gate.feed(makePacket(length: 33, up: true), up: true).isEmpty)
        XCTAssertTrue(gate.feed(makePacket(length: 99, up: true), up: true).isEmpty)

        var emitted: [UDPPacket] = []
        for item in UploadGate.handshakePrefix.dropFirst() {
            emitted = gate.feed(makePacket(length: item.length, up: item.up), up: item.up)
        }

        XCTAssertEqual(emitted.count, UploadGate.handshakePrefix.count + 1)
        XCTAssertEqual(emitted.map { $0.payload.count }[1], 99, "杂物按到达顺序夹在第 1、2 项之间")
        XCTAssertEqual(gate.gameFlows, 1)
    }

    func testTracksTwoFlowsIndependently() {
        let gate = UploadGate()
        var emitted = 0
        for item in UploadGate.handshakePrefix {
            emitted += gate.feed(makePacket(length: item.length, up: item.up, port: 65010), up: item.up).count
            emitted += gate.feed(makePacket(length: item.length, up: item.up, port: 65011), up: item.up).count
        }
        XCTAssertEqual(gate.gameFlows, 2)
        XCTAssertEqual(emitted, UploadGate.handshakePrefix.count * 2)
    }

    func testUpstreamOnlyFlowIsAbandoned() {
        let gate = UploadGate()
        var emitted = 0
        // 全是上行 33 字节：第 2 项要的是下行 25，永远等不到
        for _ in 0..<UploadGate.handshakeProbeLimit {
            emitted += gate.feed(makePacket(length: 33, up: true), up: true).count
        }
        XCTAssertEqual(emitted, 0)
        XCTAssertEqual(gate.gameFlows, 0)
        XCTAssertEqual(gate.trackedFlows, 0, "缓冲超限后应放弃该流，不再为它留内存")
        XCTAssertEqual(gate.signatureFiltered, UploadGate.handshakeProbeLimit)
    }

    func testRandomFlowNeverStartsTracking() {
        let gate = UploadGate()
        // 首包长度不是签名开头，连跟踪都不开始
        XCTAssertTrue(gate.feed(makePacket(length: 77, up: true), up: true).isEmpty)
        XCTAssertEqual(gate.trackedFlows, 0)
        XCTAssertEqual(gate.signatureFiltered, 1)
    }

    func testEvictsIdleFlowsWhenTableIsFull() {
        var now: TimeInterval = 1_000
        let gate = UploadGate(clock: { now })
        for offset in 0..<UploadGate.maxTrackedFlows {
            _ = gate.feed(makePacket(length: 33, up: true, port: UInt16(10_000 + offset)), up: true)
        }
        XCTAssertEqual(gate.trackedFlows, UploadGate.maxTrackedFlows)

        // 全部空闲过久：新流进来时先清掉，而不是把它挡在门外
        now += UploadGate.flowIdleSeconds + 1
        _ = gate.feed(makePacket(length: 33, up: true), up: true)
        XCTAssertEqual(gate.trackedFlows, 1)
    }

    // MARK: - ② 私网过滤

    func testPrivateRemoteIsNeverReported() {
        let gate = UploadGate()
        let packet = UDPPacket(
            src: client,
            dst: "192.168.1.30",
            sport: clientPort,
            dport: remotePort,
            payload: [UInt8](repeating: 1, count: 33)
        )
        XCTAssertTrue(gate.feed(packet, up: true).isEmpty)
        XCTAssertEqual(gate.ignored, 1)
        XCTAssertEqual(gate.trackedFlows, 0)
    }

    func testPrivateAddressRecognition() {
        for host in ["10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
                     "169.254.1.1", "127.0.0.1", "fe80::1", "::1"] {
            XCTAssertTrue(UploadGate.isPrivate(host), "\(host) 应判为内网")
        }
        for host in ["8.8.8.8", "172.32.0.1", "192.169.1.1", "203.0.113.7",
                     "2001:db8::1", "game.example.com", ""] {
            XCTAssertFalse(UploadGate.isPrivate(host), "\(host) 不该判为内网")
        }
    }

    // MARK: - IPv4 数据报组装

    func testBuildsIPv4UDPDatagram() {
        let payload: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        let datagram = IPDatagram.make(
            src: "1.2.3.4", dst: "5.6.7.8", sport: 40000, dport: 65010, payload: payload
        )
        let bytes = try? XCTUnwrap(datagram)
        guard let bytes else { return }

        XCTAssertEqual(bytes.count, 20 + 8 + payload.count)
        XCTAssertEqual(bytes[0], 0x45, "版本 4 + 头长 5")
        XCTAssertEqual((Int(bytes[2]) << 8) | Int(bytes[3]), bytes.count, "总长度")
        XCTAssertEqual(bytes[8], 64, "TTL")
        XCTAssertEqual(bytes[9], IPDatagram.protocolUDP)
        XCTAssertEqual(Array(bytes[12..<16]), [1, 2, 3, 4])
        XCTAssertEqual(Array(bytes[16..<20]), [5, 6, 7, 8])
        XCTAssertEqual(Array(bytes[20..<22]), [0x9C, 0x40], "源端口 40000")
        XCTAssertEqual(Array(bytes[22..<24]), [0xFD, 0xF2], "目的端口 65010")
        XCTAssertEqual((Int(bytes[24]) << 8) | Int(bytes[25]), 8 + payload.count, "UDP 长度")
        XCTAssertEqual(Array(bytes[28...]), payload, "载荷必须逐字节一致")
    }

    func testChecksumsVerifyToZero() {
        let datagram = IPDatagram.make(
            src: "1.2.3.4", dst: "5.6.7.8", sport: 40000, dport: 65010, payload: [1, 2, 3, 4]
        )
        guard let datagram else { return XCTFail("组装失败") }

        // 校验和自身的性质：把它填进去之后，整段再算一遍必得 0
        XCTAssertEqual(IPDatagram.checksum(Array(datagram[0..<20])), 0, "IP 头校验和")
        let udpLength = (Int(datagram[24]) << 8) | Int(datagram[25])
        let udp = Array(datagram[20..<(20 + udpLength)])
        var pseudo = Array(datagram[12..<20])
        pseudo.append(contentsOf: [0, IPDatagram.protocolUDP])
        pseudo.append(contentsOf: [datagram[24], datagram[25]])
        XCTAssertEqual(IPDatagram.checksum(pseudo + udp), 0, "UDP 校验和（带伪首部）")
    }

    func testChecksumMatchesRFC1071Example() {
        // RFC 1071 §3 的经典例子
        let sample: [UInt8] = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]
        XCTAssertEqual(IPDatagram.checksum(sample), 0x220D)
        // 奇数长度按尾部补 0 处理
        XCTAssertEqual(IPDatagram.checksum([0x00, 0x01, 0xf2]), IPDatagram.checksum([0x00, 0x01, 0xf2, 0x00]))
    }

    func testRefusesNonIPv4Remote() {
        XCTAssertNil(IPDatagram.make(
            src: "1.2.3.4", dst: "game.example.com", sport: 1, dport: 2, payload: [1]
        ))
        XCTAssertNil(IPDatagram.make(
            src: "1.2.3.4", dst: "2001:db8::1", sport: 1, dport: 2, payload: [1]
        ))
    }
}
