import XCTest
@testable import StarRadarCore

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
        let clientKey = try XCTUnwrap(
            clientSide.deriveKey(peerPublic: try TGCP.parseDHPublic(header: forwarded.header).value)
        )

        let returned = try singleFrame(
            try session.process(
                makeTGCPFrame(command: TGCP.commandServerHello, dhPublic: serverSide.publicBytes),
                direction: .serverToClient
            )
        )
        let serverKey = try XCTUnwrap(
            serverSide.deriveKey(peerPublic: try TGCP.parseDHPublic(header: returned.header).value)
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
