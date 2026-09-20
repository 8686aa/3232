import XCTest
@testable import StarRadarCore

/// 手写 WebSocket 的接线部分：升级握手与帧编解码。
/// 这两块是纯函数，正好可以脱离真机、脱离 socket 直接对着规范验。
final class WebSocketWireTests: XCTestCase {

    // MARK: - 握手

    /// RFC 6455 §1.3 的黄金向量，用来证明 accept 算法没写错
    func testAcceptMatchesRFC6455GoldenVector() {
        XCTAssertEqual(
            WebSocketHandshake.accept(for: "dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        )
    }

    func testRequestIsAValidUpgradeRequest() throws {
        let request = WebSocketHandshake.request(host: "192.168.110.152", port: 1082, key: "AAAA")
        let text = try XCTUnwrap(String(data: request, encoding: .utf8))

        XCTAssertTrue(text.hasPrefix("GET / HTTP/1.1\r\n"))
        XCTAssertTrue(text.contains("\r\nHost: 192.168.110.152:1082\r\n"))
        XCTAssertTrue(text.contains("\r\nUpgrade: websocket\r\n"))
        XCTAssertTrue(text.contains("\r\nConnection: Upgrade\r\n"))
        XCTAssertTrue(text.contains("\r\nSec-WebSocket-Key: AAAA\r\n"))
        XCTAssertTrue(text.contains("\r\nSec-WebSocket-Version: 13\r\n"))
        XCTAssertTrue(text.hasSuffix("\r\n\r\n"))
    }

    func testMakeKeyIs16RandomBytes() {
        let key = WebSocketHandshake.makeKey()
        XCTAssertEqual(Data(base64Encoded: key)?.count, 16)
        XCTAssertNotEqual(key, WebSocketHandshake.makeKey())
    }

    func testParseAccepts101() throws {
        let raw = "HTTP/1.1 101 Switching Protocols\r\n"
            + "Upgrade: websocket\r\n"
            + "Connection: Upgrade\r\n"
            + "sec-websocket-accept:  abc \r\n\r\n"
        let response = try XCTUnwrap(WebSocketHandshake.parse(Data(raw.utf8)))
        XCTAssertEqual(response.status, 101)
        // 首尾空白要去掉，大小写不敏感
        XCTAssertEqual(response.accept, "abc")
    }

    func testParseReportsNon101Status() throws {
        // 服务端是 Fleck，对非 WebSocket 请求直接回 400 —— 要能看到这个码
        let response = try XCTUnwrap(WebSocketHandshake.parse(Data("HTTP/1.1 400 Bad Request\r\n\r\n".utf8)))
        XCTAssertEqual(response.status, 400)
        XCTAssertNil(response.accept)
    }

    /// 响应头没收全时必须返回 nil，由外层继续等下一段，不能当成解析失败
    func testParseWaitsForCompleteHeaders() {
        XCTAssertNil(WebSocketHandshake.parse(Data("HTTP/1.1 101 Switching".utf8)))
    }

    /// 响应头后面紧跟业务帧时要算准 consumed，一个字节都不能漏
    func testParseLeavesTrailingBytesToFrames() throws {
        var buffer = Data("HTTP/1.1 101 OK\r\nSec-WebSocket-Accept: abc\r\n\r\n".utf8)
        let frameBytes: [UInt8] = [0x81, 0x02, 0x68, 0x69]
        buffer.append(contentsOf: frameBytes)

        let response = try XCTUnwrap(WebSocketHandshake.parse(buffer))
        let leftover = [UInt8](buffer.dropFirst(response.consumed))
        XCTAssertEqual(leftover, frameBytes)
    }

    // MARK: - 帧

    func testEncodedTextFrameRoundTrips() {
        let payload = [UInt8]("{\"type\":\"ping\"}".utf8)
        var decoder = WebSocketFrameDecoder()
        XCTAssertEqual(decoder.append(WebSocketFrameEncoder.encode(opcode: .text, payload: payload)), [
            .text("{\"type\":\"ping\"}")
        ])
    }

    /// 客户端发出的帧必须带掩码位，否则服务端应当直接断开
    func testEncodedFrameIsMasked() {
        let frame = WebSocketFrameEncoder.encode(opcode: .text, payload: [1, 2, 3])
        XCTAssertNotEqual(frame[1] & 0x80, 0)
        XCTAssertEqual(frame[1] & 0x7F, 3)
        // 掩码 key 之后才是载荷，长度对得上
        XCTAssertEqual(frame.count, 2 + 4 + 3)
    }

    /// 长度走 126 分支：两字节扩展长度
    func testDecodesExtendedLengthFrame() {
        let payload = [UInt8](repeating: 0x41, count: 300)
        var frame: [UInt8] = [0x82, 126, UInt8(payload.count >> 8), UInt8(payload.count & 0xFF)]
        frame.append(contentsOf: payload)

        var decoder = WebSocketFrameDecoder()
        XCTAssertEqual(decoder.append(frame), [.binary(300)])
    }

    func testDecodesFragmentedText() {
        var decoder = WebSocketFrameDecoder()
        // 起始文本帧 fin=0，随后一个 fin=1 的续帧
        XCTAssertEqual(decoder.append([0x01, 0x02, 0x68, 0x65]), [])
        XCTAssertEqual(decoder.append([0x80, 0x03, 0x6C, 0x6C, 0x6F]), [.text("hello")])
    }

    /// 半帧分两次喂进来，攒够之前不能吐事件
    func testDecodesFrameSplitAcrossChunks() {
        var decoder = WebSocketFrameDecoder()
        XCTAssertEqual(decoder.append([0x81]), [])
        XCTAssertEqual(decoder.append([0x03, 0x61]), [])
        XCTAssertEqual(decoder.append([0x62, 0x63]), [.text("abc")])
    }

    func testDecodesControlFrames() {
        var decoder = WebSocketFrameDecoder()
        XCTAssertEqual(decoder.append([0x89, 0x02, 0x01, 0x02]), [.ping([1, 2])])
        XCTAssertEqual(decoder.append([0x8A, 0x00]), [.pong])
        XCTAssertEqual(decoder.append([0x88, 0x02, 0x03, 0xE8]), [.close(1000)])
    }

    func testDecodesCloseWithoutCode() {
        var decoder = WebSocketFrameDecoder()
        XCTAssertEqual(decoder.append([0x88, 0x00]), [.close(nil)])
    }

    /// 服务端通常不加掩码，但加了掩码也得解对（RFC 允许）
    func testDecodesMaskedServerFrame() {
        var decoder = WebSocketFrameDecoder()
        // fin + text，mask 位开，长度 2，掩码 key 0x01 0x02 0x03 0x04，
        // 载荷 "hi" 逐字节异或后是 0x69 0x6B
        XCTAssertEqual(
            decoder.append([0x81, 0x82, 0x01, 0x02, 0x03, 0x04, 0x69, 0x6B]),
            [.text("hi")]
        )
    }

    func testDecodesMultipleFramesInOneChunk() {
        var decoder = WebSocketFrameDecoder()
        XCTAssertEqual(
            decoder.append([0x81, 0x61, 0x81, 0x62, 0x81, 0x63]),
            [.text("a"), .text("b"), .text("c")]
        )
    }

    /// 长度字段离谱时清空缓冲，不能让对端把内存吃满
    func testRejectsAbsurdPayloadLength() {
        var decoder = WebSocketFrameDecoder()
        let frame: [UInt8] = [0x82, 127, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        XCTAssertEqual(decoder.append(frame), [])
    }
}
