import CryptoKit
import XCTest
@testable import StarRadarCore

/// 给逐帧日志里的公钥摘要当对照组
func sha256Hex(_ bytes: [UInt8]) -> String {
    SHA256.hash(data: Data(bytes)).map { String(format: "%02x", $0) }.joined()
}

/// 原生填充方案与原实现逐长度对齐：尾部 6 字节 = `tsf4g` + 填充计数，
/// 且填充计数**包含**这 6 字节，所以 pad ∈ [6, 21] 且 size + pad 必为 16 的倍数。
final class NativeAESTests: XCTestCase {
    func testPadLengthAlwaysAligns() {
        for size in 1...4095 {
            let pad = NativeAES.padLength(for: size)
            XCTAssertEqual((size + pad) % 16, 0, "size=\(size) 的填充没有对齐")
            XCTAssertEqual(pad, NativeAES.padLength(for: size))
            XCTAssertTrue(pad >= TGCP.trailerSize, "size=\(size) 的填充装不下尾标")
        }
    }

    func testPadStripRoundTrip() throws {
        for size in 1...512 {
            let body = (0..<size).map { UInt8($0 & 0xFF) }
            let padded = NativeAES.pad(body)
            XCTAssertEqual(padded.count % 16, 0, "size=\(size) 补齐后不是块整数倍")
            XCTAssertEqual(try NativeAES.strip(padded), body, "size=\(size) 往返不一致")
        }
    }

    func testStripRejectsMissingTrailer() {
        var padded = NativeAES.pad(Array(repeating: 0x41, count: 8))
        padded[padded.count - 2] = 0x00 // 破坏填充计数前的尾标
        XCTAssertThrowsError(try NativeAES.strip(padded))
    }

    func testEncryptDecryptRoundTrip() throws {
        let key = Array(UInt8(0)...UInt8(15))
        let padded = NativeAES.pad(Array("battle-material".utf8))
        let cipher = try NativeAES.encrypt(padded, key: key)
        XCTAssertEqual(cipher.count, padded.count)
        XCTAssertEqual(try NativeAES.decrypt(cipher, key: key), padded)
    }

    /// 翻译必须重新加密「解出来的 padded」，重新填充会改掉尾部字节
    func testTranslateKeepsPaddedBytes() throws {
        let source = Array(repeating: UInt8(0x11), count: 16)
        let destination = Array(repeating: UInt8(0x22), count: 16)
        let plain: [UInt8] = Array("app-payload".utf8)
        let padded = NativeAES.pad(plain)

        let result = try NativeAES.translate(
            body: try NativeAES.encrypt(padded, key: source),
            source: source,
            destination: destination
        )
        XCTAssertEqual(result.plain, plain)
        XCTAssertEqual(try NativeAES.decrypt(result.cipher, key: destination), padded)
    }

    func testTranslateRejectsMisalignedBody() {
        XCTAssertThrowsError(
            try NativeAES.translate(body: Array(repeating: 0, count: 15), source: [], destination: [])
        )
    }
}

final class TGCPTests: XCTestCase {
    func testFramerHandlesSplitFeeds() throws {
        let frame = makeTGCPFrame(command: 0x2001, body: [1, 2, 3, 4, 5])
        let framer = TGCPFramer()
        XCTAssertTrue(try framer.feed(Array(frame[0..<7])).isEmpty)
        XCTAssertTrue(try framer.feed(Array(frame[7..<20])).isEmpty)
        let frames = try framer.feed(Array(frame[20...]))
        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(frames[0].body, [1, 2, 3, 4, 5])
        XCTAssertEqual(frames[0].command, 0x2001)
    }

    func testFramerHandlesBackToBackFrames() throws {
        let first = makeTGCPFrame(command: 0x2001, sequence: 1, body: [9])
        let second = makeTGCPFrame(command: 0x2002, sequence: 2, body: [8, 7])
        let frames = try splitFrames(first + second)
        XCTAssertEqual(frames.map(\.command), [0x2001, 0x2002])
        XCTAssertEqual(frames[1].streamOffset, first.count)
    }

    func testFramerRejectsForeignStream() {
        let framer = TGCPFramer()
        XCTAssertThrowsError(try framer.feed(Array("GET / HTTP/1.1\r\n\r\nhello".utf8)))
    }

    func testDHPublicParseAndReplace() throws {
        let original = (0..<TGCP.publicBytesMax).map { UInt8($0 + 1) }
        let replacement = (0..<TGCP.publicBytesMax).map { UInt8(0xFF - $0) }
        let header = try singleFrame(
            makeTGCPFrame(command: TGCP.commandClientHello, dhPublic: original)
        ).header

        XCTAssertEqual(try TGCP.parseDHPublic(header: header).value, BigUInt(bigEndianBytes: original))

        let replaced = try TGCP.replacingDHPublic(header: header, with: replacement)
        XCTAssertEqual(try TGCP.parseDHPublic(header: replaced).value, BigUInt(bigEndianBytes: replacement))
        XCTAssertEqual(replaced.count, header.count, "等长替换不应改变头长")
        XCTAssertEqual(
            ByteCoding.readUInt32BE(replaced, TGCP.headerLengthOffset),
            UInt32(replaced.count),
            "头长字段没有回写"
        )
    }

    func testDHPublicReplaceWithShorterKeyUpdatesHeaderLength() throws {
        let header = try singleFrame(
            makeTGCPFrame(command: TGCP.commandClientHello, dhPublic: (0..<64).map { UInt8($0 + 1) })
        ).header
        let shorter = (0..<32).map { UInt8(0x80 + $0) }

        let replaced = try TGCP.replacingDHPublic(header: header, with: shorter)
        XCTAssertEqual(replaced.count, header.count - 32)
        XCTAssertEqual(ByteCoding.readUInt16BE(replaced, TGCP.extensionOffset + 1), 32)
        XCTAssertEqual(
            ByteCoding.readUInt32BE(replaced, TGCP.headerLengthOffset),
            UInt32(replaced.count)
        )
        XCTAssertEqual(try TGCP.parseDHPublic(header: replaced).value, BigUInt(bigEndianBytes: shorter))
    }
}

final class RawDHTests: XCTestCase {
    func testSharedSecretMatchesBothSides() throws {
        let alice = RawDHSide.create()
        let bob = RawDHSide.create()
        let aliceKey = try XCTUnwrap(alice.deriveKey(peerPublic: bob.publicValue))
        let bobKey = try XCTUnwrap(bob.deriveKey(peerPublic: alice.publicValue))
        XCTAssertEqual(aliceKey, bobKey)
        XCTAssertEqual(aliceKey.count, 16, "key = MD5(minimal_be(shared)) 应为 16 字节")
    }

    func testPublicBytesAreFixedWidth() {
        for _ in 0..<16 {
            let side = RawDHSide.create()
            XCTAssertEqual(side.publicBytes.count, RawDH.publicBytes)
        }
    }

    func testRejectsDegeneratePeerPublic() {
        let side = RawDHSide.create()
        XCTAssertNil(side.deriveKey(peerPublic: BigUInt(1)))
        XCTAssertNil(side.deriveKey(peerPublic: RawDH.prime))
        XCTAssertNil(side.deriveKey(peerPublic: BigUInt(0)))
    }

    func testModPowMatchesSmallReference() {
        // 与 Python 的 pow(base, exp, mod) 对照
        let cases: [(UInt64, UInt64, UInt64, UInt64)] = [
            (2, 10, 1000, 24),
            (5, 117, 19, 1),
            (7, 0, 13, 1),
            (123456, 789, 1000003, UInt64(123456).powMod(789, 1000003)),
        ]
        for (base, exponent, modulus, expected) in cases {
            let value = BigUInt.modPow(
                base: BigUInt(base),
                exponent: BigUInt(exponent),
                modulus: BigUInt(modulus)
            )
            XCTAssertEqual(value, BigUInt(expected), "\(base)^\(exponent) mod \(modulus)")
        }
    }
}

private extension UInt64 {
    /// 参考实现，只用溢出乘加，用来给 BigUInt 当对照组
    func powMod(_ exponent: UInt64, _ modulus: UInt64) -> UInt64 {
        var result: UInt64 = 1
        var base = self % modulus
        var remaining = exponent
        while remaining > 0 {
            if remaining & 1 == 1 {
                result = (result &* base) % modulus
            }
            base = (base &* base) % modulus
            remaining >>= 1
        }
        return result
    }
}

final class SOCKS5MessageTests: XCTestCase {
    func testGreetingParsesMethodList() throws {
        let greeting = try XCTUnwrap(SOCKS5Message.parseGreeting([0x05, 0x02, 0x00, 0x02]))
        XCTAssertEqual(greeting.methods, [0x00, 0x02])
        XCTAssertTrue(greeting.offersNoAuth)
    }

    func testGreetingWaitsForAllMethods() throws {
        XCTAssertNil(try SOCKS5Message.parseGreeting([0x05, 0x02, 0x00]))
        XCTAssertThrowsError(try SOCKS5Message.parseGreeting([0x04, 0x01, 0x00]))
    }

    /// 握手与请求挤在同一个包里时，切掉握手前缀后必须还能解析出请求
    func testRequestParsesAfterGreetingIsConsumed() throws {
        let greeting: [UInt8] = [0x05, 0x01, 0x00]
        let address = try XCTUnwrap(SOCKS5Address(ipv4: "10.0.0.7", port: 158))
        let request: [UInt8] = [0x05, 0x01, 0x00] + address.wireBytes

        var buffer = greeting + request
        let parsedGreeting = try XCTUnwrap(SOCKS5Message.parseGreeting(buffer))
        buffer.removeFirst(2 + parsedGreeting.methods.count)

        let parsed = try XCTUnwrap(SOCKS5Message.parseRequest(buffer))
        XCTAssertEqual(parsed.command, .connect)
        XCTAssertEqual(parsed.address.hostPort, "10.0.0.7:158")
        XCTAssertEqual(parsed.consumedBytes, request.count)
    }

    func testRequestKeepsTrailingApplicationData() throws {
        let address = try XCTUnwrap(SOCKS5Address(ipv4: "10.0.0.7", port: 158))
        let request = try XCTUnwrap(
            SOCKS5Message.parseRequest([0x05, 0x01, 0x00] + address.wireBytes + [0xAA, 0xBB])
        )
        XCTAssertEqual(request.consumedBytes, 3 + address.wireBytes.count)
    }

    func testRequestParsesDomainAddress() throws {
        let address = try XCTUnwrap(SOCKS5Address(domain: "game.example.com", port: 158))
        let request = try XCTUnwrap(
            SOCKS5Message.parseRequest([0x05, 0x03, 0x00] + address.wireBytes)
        )
        XCTAssertEqual(request.command, .udpAssociate)
        XCTAssertEqual(request.address.type, .domain)
        XCTAssertEqual(request.address.host, "game.example.com")
        XCTAssertEqual(request.address.port, 158)
    }

    func testRequestRejectsBadReservedByte() {
        XCTAssertThrowsError(
            try SOCKS5Message.parseRequest([0x05, 0x01, 0x01, 0x01, 10, 0, 0, 7, 0, 158])
        )
    }

    func testDatagramRoundTrip() throws {
        let address = try XCTUnwrap(SOCKS5Address(ipv4: "192.168.1.9", port: 4000))
        let datagram = SOCKS5Message.Datagram(address: address, payload: [1, 2, 3, 4, 5])
        let parsed = try XCTUnwrap(SOCKS5Message.parseDatagram(SOCKS5Message.encodeDatagram(datagram)))
        XCTAssertEqual(parsed.address, address)
        XCTAssertEqual(parsed.payload, [1, 2, 3, 4, 5])
    }

    func testDatagramRejectsFragments() throws {
        let address = try XCTUnwrap(SOCKS5Address(ipv4: "192.168.1.9", port: 4000))
        var bytes: [UInt8] = [0x00, 0x00, 0x01] // FRAG = 1
        bytes.append(contentsOf: address.wireBytes)
        bytes.append(contentsOf: [9, 9])
        XCTAssertThrowsError(try SOCKS5Message.parseDatagram(bytes))
    }

    func testReplyWireFormat() throws {
        let address = try XCTUnwrap(SOCKS5Address(ipv4: "127.0.0.1", port: 1080))
        XCTAssertEqual(
            SOCKS5Message.encodeReply(.succeeded, address: address),
            [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38]
        )
    }
}

final class MiddlemanSessionTests: XCTestCase {
    /// 中间人夹在两端之间：两侧看到的公钥都不是对方发的那一份，且只在自己这侧能算出通话密钥
    func testHandshakeInterceptsBothDirections() throws {
        let session = MiddlemanSession(counter: StatsCounter())
        let clientSide = RawDHSide.create()
        let serverSide = RawDHSide.create()

        let clientHello = makeTGCPFrame(command: TGCP.commandClientHello, dhPublic: clientSide.publicBytes)
        let forwarded = try singleFrame(try session.process(clientHello, direction: .clientToServer))
        XCTAssertEqual(forwarded.header.count, clientHello.count, "等长替换不该改头长")
        XCTAssertNotEqual(
            try TGCP.parseDHPublic(header: forwarded.header).value,
            clientSide.publicValue,
            "发给服务端的应该是中间人自己的公钥"
        )
        XCTAssertTrue(session.sawClientHello)
        XCTAssertFalse(session.isReady, "只有一侧密钥时不该算就绪")

        let serverHello = makeTGCPFrame(command: TGCP.commandServerHello, dhPublic: serverSide.publicBytes)
        let returned = try singleFrame(try session.process(serverHello, direction: .serverToClient))
        XCTAssertNotEqual(
            try TGCP.parseDHPublic(header: returned.header).value,
            serverSide.publicValue,
            "发回客户端的应该是中间人自己的公钥"
        )
        XCTAssertTrue(session.sawServerHello)
        XCTAssertTrue(session.isReady)
    }

    /// 端到端：客户端用自己的 key 加密，中间人转成服务端能解的密文，反向同理
    func testApplicationBodyIsReEncryptedBetweenPeers() throws {
        let session = MiddlemanSession(counter: StatsCounter())
        let clientSide = RawDHSide.create()
        let serverSide = RawDHSide.create()

        let forwarded = try singleFrame(
            try session.process(
                makeTGCPFrame(command: TGCP.commandClientHello, dhPublic: clientSide.publicBytes),
                direction: .clientToServer
            )
        )
        // 真服务端收到的是中间人冒充「客户端」的那份公钥，用它才能算出和中间人一致的 serverKey
        let serverKey = try XCTUnwrap(
            serverSide.deriveKey(peerPublic: try TGCP.parseDHPublic(header: forwarded.header).value)
        )

        let returned = try singleFrame(
            try session.process(
                makeTGCPFrame(command: TGCP.commandServerHello, dhPublic: serverSide.publicBytes),
                direction: .serverToClient
            )
        )
        // 反过来，真客户端收到的是中间人冒充「服务端」的那份公钥
        let clientKey = try XCTUnwrap(
            clientSide.deriveKey(peerPublic: try TGCP.parseDHPublic(header: returned.header).value)
        )

        // c2s：客户端密文进，服务端密钥能解的密文出
        let login = Array("battle-login".utf8)
        let upstream = try singleFrame(
            try session.process(
                makeTGCPFrame(
                    command: 0x2001,
                    gate: 1,
                    sequence: 2,
                    body: try NativeAES.encrypt(NativeAES.pad(login), key: clientKey)
                ),
                direction: .clientToServer
            )
        )
        XCTAssertEqual(try NativeAES.strip(try NativeAES.decrypt(upstream.body, key: serverKey)), login)

        // s2c：服务端密文进，客户端密钥能解的密文出，同时明文要回调给上层
        let material = Array(repeating: UInt8(0x5A), count: 128)
        var observed: [UInt8]?
        session.onPlaintext = { direction, frame, plain in
            XCTAssertEqual(direction, .serverToClient)
            XCTAssertEqual(frame.command, TGCP.commandMaterial)
            observed = plain
        }
        let downstream = try singleFrame(
            try session.process(
                makeTGCPFrame(
                    command: TGCP.commandMaterial,
                    gate: 1,
                    sequence: 3,
                    body: try NativeAES.encrypt(NativeAES.pad(material), key: serverKey)
                ),
                direction: .serverToClient
            )
        )
        XCTAssertEqual(try NativeAES.strip(try NativeAES.decrypt(downstream.body, key: clientKey)), material)
        XCTAssertEqual(observed, material)
    }

    /// gate=0 的 s2c 报文体是明文直通（原实现同样放行），别去解密把它搞坏
    func testPlaintextServerToClientPassesThrough() throws {
        let session = MiddlemanSession(counter: StatsCounter())
        let clientSide = RawDHSide.create()
        let serverSide = RawDHSide.create()
        _ = try session.process(
            makeTGCPFrame(command: TGCP.commandClientHello, dhPublic: clientSide.publicBytes),
            direction: .clientToServer
        )
        _ = try session.process(
            makeTGCPFrame(command: TGCP.commandServerHello, dhPublic: serverSide.publicBytes),
            direction: .serverToClient
        )

        let material = Array(repeating: UInt8(0x11), count: 128)
        var observed: [UInt8]?
        session.onPlaintext = { _, _, plain in observed = plain }
        let ping = makeTGCPFrame(command: 0x2002, gate: 0, sequence: 9, body: material)
        XCTAssertEqual(try session.process(ping, direction: .serverToClient), ping)
        XCTAssertEqual(observed, material)
    }

    /// 首包不像 TGCP 就整条连接退化为原样转发，别把普通 HTTPS 流量毁掉
    func testForeignStreamDegradesToPassthrough() throws {
        let session = MiddlemanSession(counter: StatsCounter())
        let tls = Array("GET / HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        XCTAssertEqual(try session.process(tls, direction: .clientToServer), tls)
        XCTAssertFalse(session.isFraming)
        XCTAssertFalse(session.isReady)
    }

    /// 逐帧日志对齐原实现 `log_frame(方向, 帧, 动作, **字段)`：
    /// 动作名固定，公钥摘要必须等于**真正发出去**的那份公钥，否则日志在骗人
    func testHandshakeFrameEventsExposePublicKeyDigests() throws {
        let session = MiddlemanSession(counter: StatsCounter())
        var events: [MiddlemanSession.FrameEvent] = []
        session.onFrame = { events.append($0) }

        let clientSide = RawDHSide.create()
        let serverSide = RawDHSide.create()
        let forwarded = try singleFrame(try session.process(
            makeTGCPFrame(command: TGCP.commandClientHello, dhPublic: clientSide.publicBytes),
            direction: .clientToServer
        ))
        let returned = try singleFrame(try session.process(
            makeTGCPFrame(command: TGCP.commandServerHello, dhPublic: serverSide.publicBytes),
            direction: .serverToClient
        ))

        XCTAssertEqual(events.map(\.action), ["rewrite-client-hello", "rewrite-server-hello"])
        XCTAssertEqual(events[0].direction, .clientToServer)
        XCTAssertEqual(events[0].command, TGCP.commandClientHello)

        let clientHello = Dictionary(uniqueKeysWithValues: events[0].fields)
        XCTAssertEqual(clientHello["peer_public_sha256"], sha256Hex(clientSide.publicBytes))
        XCTAssertEqual(
            clientHello["replacement_public_sha256"],
            sha256Hex(try forwardedPublicDigestSource(forwarded))
        )
        XCTAssertEqual(clientHello["client_key_ready"], "true")

        let serverHello = Dictionary(uniqueKeysWithValues: events[1].fields)
        XCTAssertEqual(serverHello["peer_public_sha256"], sha256Hex(serverSide.publicBytes))
        XCTAssertEqual(
            serverHello["replacement_public_sha256"],
            sha256Hex(try forwardedPublicDigestSource(returned))
        )
        XCTAssertEqual(serverHello["server_key_ready"], "true")
        XCTAssertEqual(serverHello["body_translated"], "false")
        XCTAssertEqual(serverHello["new_body_len"], "0")
    }

    /// `translate-body` 报出解密前后长度；同一「方向:指令:动作」只记一条，避免按帧刷屏
    func testApplicationFrameEventsReportLengthsAndDeduplicate() throws {
        let session = MiddlemanSession(counter: StatsCounter())
        var events: [MiddlemanSession.FrameEvent] = []
        session.onFrame = { events.append($0) }

        let clientSide = RawDHSide.create()
        let serverSide = RawDHSide.create()
        let forwarded = try singleFrame(try session.process(
            makeTGCPFrame(command: TGCP.commandClientHello, dhPublic: clientSide.publicBytes),
            direction: .clientToServer
        ))
        let serverKey = try XCTUnwrap(
            serverSide.deriveKey(peerPublic: try TGCP.parseDHPublic(header: forwarded.header).value)
        )
        let returned = try singleFrame(try session.process(
            makeTGCPFrame(command: TGCP.commandServerHello, dhPublic: serverSide.publicBytes),
            direction: .serverToClient
        ))
        let clientKey = try XCTUnwrap(
            clientSide.deriveKey(peerPublic: try TGCP.parseDHPublic(header: returned.header).value)
        )
        events.removeAll()

        let payload = Array("battle-material".utf8)
        let padded = NativeAES.pad(payload)
        let frame = makeTGCPFrame(
            command: 0x2001,
            gate: 1,
            sequence: 7,
            body: try NativeAES.encrypt(padded, key: clientKey)
        )
        let first = try singleFrame(try session.process(frame, direction: .clientToServer))
        XCTAssertEqual(try NativeAES.strip(try NativeAES.decrypt(first.body, key: serverKey)), payload)
        // 同样的密文再来一遍：翻译照样执行，日志不该再出一条
        _ = try session.process(frame, direction: .clientToServer)

        XCTAssertEqual(events.map(\.action), ["translate-body"], "重复动作只该记一次")
        let fields = Dictionary(uniqueKeysWithValues: events[0].fields)
        XCTAssertEqual(fields["plain_len"], "\(payload.count)")
        XCTAssertEqual(fields["new_body_len"], "\(padded.count)")
        XCTAssertEqual(events[0].sequence, 7)
        XCTAssertEqual(events[0].gate, 1)
    }

    /// gate=0 的 s2c 直通也要留一条 `pass-plaintext`，否则「捞不到候选」时无从判断是没材料还是没走到
    func testPlaintextPassIsLoggedOnce() throws {
        let session = MiddlemanSession(counter: StatsCounter())
        let clientSide = RawDHSide.create()
        let serverSide = RawDHSide.create()
        _ = try session.process(
            makeTGCPFrame(command: TGCP.commandClientHello, dhPublic: clientSide.publicBytes),
            direction: .clientToServer
        )
        _ = try session.process(
            makeTGCPFrame(command: TGCP.commandServerHello, dhPublic: serverSide.publicBytes),
            direction: .serverToClient
        )

        var events: [MiddlemanSession.FrameEvent] = []
        session.onFrame = { events.append($0) }
        let ping = makeTGCPFrame(command: 0x2002, gate: 0, sequence: 9, body: [UInt8](repeating: 0, count: 8))
        _ = try session.process(ping, direction: .serverToClient)
        _ = try session.process(ping, direction: .serverToClient)
        XCTAssertEqual(events.map(\.action), ["pass-plaintext"])
    }
}

/// 从帧头里取公钥，补成定长大端 —— 与中间人算摘要前的处理一致
private func forwardedPublicDigestSource(_ frame: TGCPFrame) throws -> [UInt8] {
    try XCTUnwrap(
        TGCP.parseDHPublic(header: frame.header).value.bigEndianBytes(fixedSize: RawDH.publicBytes)
    )
}

final class MaterialExtractorTests: XCTestCase {
    /// 128 字节材料的 base64 是 172 字符，正好落在原实现 160…220 的窗口里
    func testExtractsMaterialFromBase64Blob() throws {
        let material = (0..<128).map { UInt8($0) }
        let blob = Data(material).base64EncodedString()
        XCTAssertEqual(blob.count, 172)

        let plain = Array("prefix|\(blob)|suffix".utf8)
        let candidates = MaterialExtractor.candidates(in: plain).filter { $0.layer == "plain" }
        XCTAssertEqual(candidates.count, 1)
        XCTAssertEqual(candidates.first?.material, material)
        XCTAssertEqual(candidates.first?.offset, 7)
        // 明文比窗口还短，上下文就是整段明文
        XCTAssertEqual(candidates.first?.context, plain)
    }

    /// 偏移必须是**字节**偏移。命中处前面夹了多字节字符时，
    /// 按「字符数」算会算少（实战报文里二进制字节遍地都是，这个坑必踩）
    func testOffsetCountsBytesNotCharacters() {
        let material = (0..<128).map { UInt8($0) }
        let blob = Array(Data(material).base64EncodedString().utf8)
        let prefix = Array("战斗!".utf8)
        XCTAssertEqual(prefix.count, 7, "三个字符共 7 字节")

        let candidate = MaterialExtractor.candidates(in: prefix + blob).first { $0.layer == "plain" }
        XCTAssertEqual(candidate?.offset, prefix.count)
        XCTAssertEqual(candidate?.material, material)
    }

    /// 上下文取命中处前后各 2048 字节，并贴边裁剪
    func testContextWindowIsClampedToLayerBounds() {
        let material = (0..<128).map { UInt8($0) }
        let blob = Data(material).base64EncodedString()
        // 用非 base64 字符填充，免得被当成更长的候选
        let padding = String(repeating: "|", count: 3000)
        let plain = Array("\(padding)\(blob)\(padding)".utf8)

        let candidate = MaterialExtractor.candidates(in: plain).first { $0.layer == "plain" }
        XCTAssertEqual(candidate?.offset, 3000)
        XCTAssertEqual(
            candidate?.context.count,
            MaterialExtractor.contextRadius * 2 + blob.utf8.count,
            "两侧各 2048 加命中段本身"
        )
    }

    func testIgnoresBlobsOfWrongLength() {
        let short = Data((0..<64).map { UInt8($0) }).base64EncodedString()
        XCTAssertTrue(MaterialExtractor.candidates(in: Array(short.utf8)).isEmpty)
    }

    /// 明文层永远在，LZ4 层只在真的能解出不同内容时追加
    func testLayersAlwaysIncludePlain() {
        let layers = MaterialExtractor.layers(Array("not lz4 at all".utf8))
        XCTAssertEqual(layers.map(\.name), ["plain"])
    }
}

final class HexCodingTests: XCTestCase {
    func testRoundTripOverEveryByte() {
        let bytes = (0...255).map { UInt8($0) }
        XCTAssertEqual(Hex.encode(bytes).count, 512)
        XCTAssertEqual(Hex.decode(Hex.encode(bytes)), bytes)
        XCTAssertEqual(Hex.encode([0x00, 0x0F, 0xFF]), "000fff", "必须小写")
    }

    func testDecodeRejectsMalformedInput() {
        XCTAssertNil(Hex.decode("0fF"), "奇数长度不该成功")
        XCTAssertNil(Hex.decode("0g"))
        XCTAssertNil(Hex.decode(" "))
        // 全角 ａ 是 3 字节 UTF-8，`Character.isHexDigit` 会放它过去，这里必须挡住
        XCTAssertNil(Hex.decode("ａ1"))
    }

    func testSingleCharacterValue() {
        XCTAssertEqual(Hex.value(of: UInt8(ascii: "0")), 0)
        XCTAssertEqual(Hex.value(of: UInt8(ascii: "9")), 9)
        XCTAssertEqual(Hex.value(of: UInt8(ascii: "a")), 10)
        XCTAssertEqual(Hex.value(of: UInt8(ascii: "F")), 15)
        XCTAssertNil(Hex.value(of: UInt8(ascii: "g")))
        XCTAssertNil(Hex.value(of: UInt8(ascii: " ")))
    }
}

/// StarRadarSecureWS v1 的黄金向量，整组取自协议文档 §10（对 C# 服务端真实跑通的记录）。
///
/// 这组断言是跨端一致性的最后一道闸：常量、字节拼接顺序、AAD 里的方向、seq 起算点，
/// 任意一处写错都会立刻红 —— 而且**必须是逐字节相等**，不能只验「能自己解开自己」。
final class SecureWSTests: XCTestCase {
    private let apiKey = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    private let clientNonce = Array(UInt8(0)...UInt8(31))
    private let serverNonce = Array(UInt8(32)...UInt8(63))

    private let roomIDHex = "9aeffe665ff5a6c27aa851d6a471b8c2a09950ec58bd92d58ea733463b4aa000"
    private let c2sKeyHex = "e4585cd93bdad6bf2988bfd056365e94ca015b005da2fa546eacbd135db6a0c9"
    private let s2cKeyHex = "a6fadafa797481bb0be715df7e2c5b90bfaf0a32489c6786a61ac0b87e8d66ad"
    private let c2sIVHex = "07c9791b"
    private let s2cIVHex = "6e901751"
    private let proofKeyHex = "a2505fe9090d4dc01eff91b9d596114ee6e6ed2419bf875f5416ebbd452f7666"
    private let serverProofHex = "1f1512bc6e288e9536c9decd20f246f4a2dbd26bf746096ea9b81833206b6947"
    private let clientProofHex = "857fdff64d93806f73a9540b469b3799b12f1334941ff697dd4c9f6d293c9da6"

    /// 服务端 → 客户端，s2c_key / seq=1
    private let downEnvelope = "{\"type\":\"enc\",\"v\":1,\"seq\":1,\"d\":\"Qud1Zkc9aLl6Zc7awxoxHSZPH53svqbhtwHeAKK8Iswe2oK2yIw9LLXw\"}"
    /// 客户端 → 服务端，c2s_key / seq=2（seq=1 被 secure_finish 占掉了）
    private let upEnvelope = "{\"type\":\"enc\",\"v\":1,\"seq\":2,\"d\":\"gtug30e65U/hRjUrAW0cLOsTFWqm+EDtdW/w232jD+SIItVmfLlaBtyraHt3oNgBFUCLDRnj8o1EzZEUpq2ssPeg\"}"
    private let batchPlaintext = "{\"batch\":[{\"data\":\"AA==\",\"k\":\"471fb943aa23c511\"}]}"

    private func goldenKeys() throws -> SecureWS.SessionKeys {
        try SecureWS.deriveKeys(apiKey: apiKey, clientNonce: clientNonce, serverNonce: serverNonce)
    }

    func testRoomIDMatchesGoldenVector() throws {
        XCTAssertEqual(SecureWS.roomID(apiKey), roomIDHex)
    }

    func testKeyDerivationMatchesGoldenVector() throws {
        let keys = try goldenKeys()
        XCTAssertEqual(Hex.encode(keys.c2sKey), c2sKeyHex)
        XCTAssertEqual(Hex.encode(keys.s2cKey), s2cKeyHex)
        XCTAssertEqual(Hex.encode(keys.c2sIV), c2sIVHex)
        XCTAssertEqual(Hex.encode(keys.s2cIV), s2cIVHex)
        XCTAssertEqual(Hex.encode(keys.proofKey), proofKeyHex)
        XCTAssertEqual(keys.c2sKey.count, 32)
        XCTAssertEqual(keys.c2sIV.count, 4, "帧 nonce 前 4 字节")
    }

    func testTranscriptAndProofsMatchGoldenVector() throws {
        let keys = try goldenKeys()
        let transcript = SecureWS.buildTranscript(
            room: SecureWS.roomID(apiKey),
            clientNonce: clientNonce,
            serverNonce: serverNonce
        )
        XCTAssertEqual(
            transcript,
            "StarRadarSecureWS1|\(roomIDHex)|\(Hex.encode(clientNonce))|\(Hex.encode(serverNonce))"
        )
        XCTAssertEqual(SecureWS.buildProof(keys: keys, transcript: transcript, side: "server"), serverProofHex)
        XCTAssertEqual(SecureWS.buildProof(keys: keys, transcript: transcript, side: "client"), clientProofHex)
    }

    /// 加密必须逐字节复现文档里的两条信封 —— AES-GCM 在 key/nonce/AAD 固定的前提下
    /// 是确定性的，所以这条比「自己加密自己能解开」强得多，能一次锁死 AAD 与 IV 拼接
    func testEncryptReproducesGoldenEnvelopes() throws {
        let keys = try goldenKeys()

        let downstream = try SecureChannel(keys: keys, outboundDir: SecureWS.dirS2C)
        XCTAssertEqual(try downstream.encrypt("{\"type\":\"secure_ok\",\"v\":1}"), downEnvelope)

        // 上行：seq=1 归 secure_finish，batch 排在 seq=2
        let upstream = try SecureChannel(keys: keys, outboundDir: SecureWS.dirC2S)
        _ = try upstream.encrypt("{\"type\":\"secure_finish\",\"v\":1,\"proof\":\"\(clientProofHex)\"}")
        XCTAssertEqual(try upstream.encrypt(batchPlaintext), upEnvelope)
    }

    func testDecryptGoldenEnvelopes() throws {
        let keys = try goldenKeys()
        // 客户端视角：出站 c2s，因此入站方向自动是 s2c
        let channel = try SecureChannel(keys: keys, outboundDir: SecureWS.dirC2S)

        let ok = try channel.decryptObject(downEnvelope)
        XCTAssertEqual(ok["type"]?.stringValue, "secure_ok")
        XCTAssertEqual(ok["v"]?.intValue, 1)
        XCTAssertEqual(channel.receivedCount, 1)
    }

    /// 服务端视角（出站 s2c，入站 c2s）才能解上行帧，且解完是那条 batch
    func testDecryptUpstreamBatchFromServerSideChannel() throws {
        let keys = try goldenKeys()
        let channel = try SecureChannel(keys: keys, outboundDir: SecureWS.dirS2C)

        // 服务端这里也有一条 seq=1 的下行（secure_ok），先占掉才能轮到 seq=2
        _ = try channel.encrypt("{\"type\":\"secure_ok\",\"v\":1}")
        let batch = try channel.decryptObject(upEnvelope)
        XCTAssertEqual(batch["batch"]?.elements?.count, 1)
        XCTAssertEqual(batch["batch"]?.elements?.first?["data"]?.stringValue, "AA==")
        XCTAssertEqual(batch["batch"]?.elements?.first?["k"]?.stringValue, "471fb943aa23c511")
    }

    /// 抗反射：把上行帧原样反射回来，方向写进了 AAD，必须解不开
    func testReflectedFrameIsRejected() throws {
        let keys = try goldenKeys()
        let channel = try SecureChannel(keys: keys, outboundDir: SecureWS.dirC2S)
        // 先吃掉下行 seq=1 把 recvSeq 推到 1，反射帧的 seq=2 才通得过序号校验，
        // 从而真的走到 GCM 认证那一步（否则只会以「seq 错」收场，测不到反射防护）
        _ = try channel.decrypt(downEnvelope)
        XCTAssertThrowsError(try channel.decrypt(upEnvelope)) { error in
            guard case SecureWSError.frameAuthenticationFailed = error else {
                return XCTFail("反射帧应因方向不符被拒，实际：\(error)")
            }
        }
    }

    /// 抗篡改：密文改一个字节就 InvalidTag
    func testTamperedFrameIsRejected() throws {
        let keys = try goldenKeys()
        let channel = try SecureChannel(keys: keys, outboundDir: SecureWS.dirC2S)
        _ = try channel.decrypt(downEnvelope)

        let document = try XCTUnwrap(JSONValue.parseObject(upEnvelope))
        let encoded = try XCTUnwrap(document["d"]?.stringValue)
        var sealed = [UInt8](try XCTUnwrap(Data(base64Encoded: encoded)))
        sealed[3] ^= 0x01
        let forged = "{\"type\":\"enc\",\"v\":1,\"seq\":2,\"d\":\"\(Data(sealed).base64EncodedString())\"}"

        XCTAssertThrowsError(try channel.decrypt(forged)) { error in
            guard case SecureWSError.frameAuthenticationFailed = error else {
                return XCTFail("被篡改的帧应认证失败，实际：\(error)")
            }
        }
    }

    /// 序号校验必须早于解密，否则「seq 不连续」和「被篡改」两件事分不开
    func testSequenceIsCheckedBeforeDecryption() throws {
        let keys = try goldenKeys()
        let channel = try SecureChannel(keys: keys, outboundDir: SecureWS.dirC2S)
        XCTAssertThrowsError(try channel.decrypt(upEnvelope)) { error in
            guard case SecureWSError.invalidSequence(let expected, let received) = error else {
                return XCTFail("首帧即 seq=2 应先报序号错，实际：\(error)")
            }
            XCTAssertEqual(expected, 1)
            XCTAssertEqual(received, 2)
        }
    }

    func testClientHandshakeSendsGoldenHelloAndFinish() throws {
        let handshake = try SecureClientHandshake(apiKey: apiKey, clientNonce: clientNonce)

        let hello = try XCTUnwrap(JSONValue.parseObject(handshake.hello()))
        XCTAssertEqual(hello["type"]?.stringValue, "secure_hello")
        XCTAssertEqual(hello["v"]?.intValue, 1)
        XCTAssertEqual(hello["api_key"]?.stringValue, apiKey)
        XCTAssertEqual(hello["nonce"]?.stringValue, Hex.encode(clientNonce))

        let challenge = "{\"type\":\"secure_challenge\",\"v\":1,"
            + "\"nonce\":\"\(Hex.encode(serverNonce))\",\"proof\":\"\(serverProofHex)\"}"
        let (channel, finish) = try handshake.acceptChallenge(challenge)

        let finishDocument = try XCTUnwrap(JSONValue.parseObject(finish))
        XCTAssertEqual(finishDocument["type"]?.stringValue, "secure_finish")
        XCTAssertEqual(finishDocument["proof"]?.stringValue, clientProofHex)

        // 握手拿到的通道正好能解第 ④ 步的 secure_ok
        XCTAssertEqual(try channel.decryptObject(downEnvelope)["type"]?.stringValue, "secure_ok")
    }

    /// 服务端 proof 不对就必须停下 —— 否则后面对着一把「双方不一致的密钥」继续发密文，
    /// 服务端只会当成认证失败断开，现场看不到任何「密钥错了」的线索
    func testClientHandshakeRejectsBadServerProof() throws {
        let handshake = try SecureClientHandshake(apiKey: apiKey, clientNonce: clientNonce)
        let bad = "{\"type\":\"secure_challenge\",\"v\":1,"
            + "\"nonce\":\"\(Hex.encode(serverNonce))\","
            + "\"proof\":\"\(String(repeating: "0", count: 64))\"}"
        XCTAssertThrowsError(try handshake.acceptChallenge(bad)) { error in
            guard case SecureWSError.serverProofRejected = error else {
                return XCTFail("应报服务端证明不通过，实际：\(error)")
            }
        }
    }

    func testHandshakeRejectsReplayOfChallenge() throws {
        let handshake = try SecureClientHandshake(apiKey: apiKey, clientNonce: clientNonce)
        let challenge = "{\"type\":\"secure_challenge\",\"v\":1,"
            + "\"nonce\":\"\(Hex.encode(serverNonce))\",\"proof\":\"\(serverProofHex)\"}"
        _ = try handshake.acceptChallenge(challenge)
        XCTAssertThrowsError(try handshake.acceptChallenge(challenge)) { error in
            guard case SecureWSError.handshakeAlreadyDone = error else {
                return XCTFail("同一次握手不该被复用，实际：\(error)")
            }
        }
    }

    func testNormalizeAPIKeyAcceptsUppercaseAndRejectsNonASCII() throws {
        XCTAssertEqual(try SecureWS.normalizeAPIKey("A1B2C3D4E5F60718293A4B5C6D7E8F90"), apiKey)
        XCTAssertEqual(try SecureWS.normalizeAPIKey("  \(apiKey)\n"), apiKey)
        XCTAssertThrowsError(try SecureWS.normalizeAPIKey("a1b2c3d4e5f60718293a4b5c6d7e8f9"), "31 位")
        XCTAssertThrowsError(try SecureWS.normalizeAPIKey("g1b2c3d4e5f60718293a4b5c6d7e8f90"), "含非 hex")
        XCTAssertThrowsError(try SecureWS.normalizeAPIKey("Ａ1b2c3d4e5f60718293a4b5c6d7e8f9"), "全角 Ａ")
    }

    func testDecodeNonceRequiresSixtyFourHexChars() throws {
        XCTAssertEqual(try SecureWS.decodeNonce(Hex.encode(serverNonce), name: "服务端 nonce"), serverNonce)
        XCTAssertThrowsError(try SecureWS.decodeNonce(nil, name: "服务端 nonce"))
        XCTAssertThrowsError(try SecureWS.decodeNonce("00", name: "服务端 nonce"), "长度不足")
        XCTAssertThrowsError(
            try SecureWS.decodeNonce(String(repeating: "z", count: 64), name: "服务端 nonce"),
            "非 hex"
        )
    }
}
