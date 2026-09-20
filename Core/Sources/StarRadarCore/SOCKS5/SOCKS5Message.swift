import Darwin
import Foundation

public enum SOCKS5Error: Error, CustomStringConvertible {
    case incomplete
    case unsupportedVersion(UInt8)
    case badReservedByte(UInt8)
    case unsupportedCommand(UInt8)
    case unsupportedAddressType(UInt8)
    case domainTooLong(Int)
    case badAddressValue(String)
    case fragmentedDatagram(UInt8)

    public var description: String {
        switch self {
        case .incomplete: return "报文不完整，需要继续读取"
        case .unsupportedVersion(let v): return "SOCKS 版本不支持：\(v)"
        case .badReservedByte(let v): return "保留字节非零：\(v)"
        case .unsupportedCommand(let v): return "命令不支持：\(v)"
        case .unsupportedAddressType(let v): return "地址类型不支持：\(v)"
        case .domainTooLong(let size): return "域名过长：\(size)"
        case .badAddressValue(let value): return "地址无法解析：\(value)"
        case .fragmentedDatagram(let frag): return "不支持分片的 UDP 数据报：FRAG=\(frag)"
        }
    }
}

public enum SOCKS5 {
    public static let version: UInt8 = 0x05

    public enum Method: UInt8 {
        case noAuth = 0x00
        case gssapi = 0x01
        case userPassword = 0x02
        case noneAcceptable = 0xFF
    }

    public enum Command: UInt8 {
        case connect = 0x01
        case bind = 0x02
        case udpAssociate = 0x03
    }

    public enum Reply: UInt8 {
        case succeeded = 0x00
        case generalFailure = 0x01
        case connectionNotAllowed = 0x02
        case networkUnreachable = 0x03
        case hostUnreachable = 0x04
        case connectionRefused = 0x05
        case ttlExpired = 0x06
        case commandNotSupported = 0x07
        case addressTypeNotSupported = 0x08
    }

    public enum AddressType: UInt8 {
        case ipv4 = 0x01
        case domain = 0x03
        case ipv6 = 0x04
    }
}

/// SOCKS5 地址。同时保留文本形式（连上游用）和线上编码（回包用）。
public struct SOCKS5Address: Equatable {
    public let type: SOCKS5.AddressType
    /// IPv4/IPv6 为点分或冒分文本，域名为原始字符串
    public let host: String
    public let port: UInt16
    /// 地址字段编码，不含 ATYP；域名带长度前缀
    public let encoded: [UInt8]

    public init(type: SOCKS5.AddressType, host: String, port: UInt16, encoded: [UInt8]) {
        self.type = type
        self.host = host
        self.port = port
        self.encoded = encoded
    }

    /// 构造 IPv4 地址，失败返回 nil
    public init?(ipv4: String, port: UInt16) {
        guard let bytes = SOCKS5Address.ipv4Bytes(ipv4) else { return nil }
        self.init(type: .ipv4, host: ipv4, port: port, encoded: bytes)
    }

    /// 构造 IPv6 地址，失败返回 nil
    public init?(ipv6: String, port: UInt16) {
        guard let bytes = SOCKS5Address.ipv6Bytes(ipv6) else { return nil }
        self.init(type: .ipv6, host: ipv6, port: port, encoded: bytes)
    }

    /// 构造域名地址
    public init?(domain: String, port: UInt16) {
        let utf8 = Array(domain.utf8)
        guard !utf8.isEmpty, utf8.count <= 255 else { return nil }
        self.init(type: .domain, host: domain, port: port, encoded: [UInt8(utf8.count)] + utf8)
    }

    /// 按目标文本自动挑类型：能解析成 IP 就用 IP，否则当域名
    public init?(host: String, port: UInt16) {
        if let value = SOCKS5Address(ipv4: host, port: port) {
            self = value
        } else if let value = SOCKS5Address(ipv6: host, port: port) {
            self = value
        } else if let value = SOCKS5Address(domain: host, port: port) {
            self = value
        } else {
            return nil
        }
    }

    /// 完整线上编码：ATYP + 地址 + 端口
    public var wireBytes: [UInt8] {
        var out: [UInt8] = [type.rawValue]
        out.append(contentsOf: encoded)
        ByteCoding.appendUInt16BE(port, to: &out)
        return out
    }

    public var hostPort: String { "\(host):\(port)" }

    static func ipv4Bytes(_ text: String) -> [UInt8]? {
        var raw = in_addr()
        guard inet_pton(AF_INET, text, &raw) == 1 else { return nil }
        return withUnsafeBytes(of: raw) { Array($0.prefix(4)) }
    }

    static func ipv6Bytes(_ text: String) -> [UInt8]? {
        var raw = in6_addr()
        guard inet_pton(AF_INET6, text, &raw) == 1 else { return nil }
        return withUnsafeBytes(of: raw) { Array($0.prefix(16)) }
    }

    static func ipv4Text(_ bytes: [UInt8]) -> String? {
        guard bytes.count == 4 else { return nil }
        var raw = in_addr()
        withUnsafeMutableBytes(of: &raw) { $0.copyBytes(from: bytes) }
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &raw, &buffer, socklen_t(buffer.count)) != nil else { return nil }
        return String(cString: buffer)
    }

    static func ipv6Text(_ bytes: [UInt8]) -> String? {
        guard bytes.count == 16 else { return nil }
        var raw = in6_addr()
        withUnsafeMutableBytes(of: &raw) { $0.copyBytes(from: bytes) }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &raw, &buffer, socklen_t(buffer.count)) != nil else { return nil }
        return String(cString: buffer)
    }
}

/// 顺序读取字节的小游标，越界返回 nil
struct ByteCursor {
    let bytes: [UInt8]
    var index: Int = 0

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    var remaining: Int { max(0, bytes.count - index) }

    mutating func readUInt8() -> UInt8? {
        guard index < bytes.count else { return nil }
        defer { index += 1 }
        return bytes[index]
    }

    mutating func readUInt16BE() -> UInt16? {
        guard index + 2 <= bytes.count else { return nil }
        defer { index += 2 }
        return (UInt16(bytes[index]) << 8) | UInt16(bytes[index + 1])
    }

    mutating func readBytes(_ count: Int) -> [UInt8]? {
        guard count >= 0, index + count <= bytes.count else { return nil }
        defer { index += count }
        return Array(bytes[index..<(index + count)])
    }

    mutating func readRest() -> [UInt8] {
        defer { index = bytes.count }
        return Array(bytes[index...])
    }
}

/// SOCKS5 报文的解析与编码。解析函数用 nil 表示「数据不够」，抛错表示「报文非法」。
public enum SOCKS5Message {
    public struct Greeting {
        public let methods: [UInt8]
        public var offersNoAuth: Bool { methods.contains(SOCKS5.Method.noAuth.rawValue) }
    }

    public struct Request {
        public let command: SOCKS5.Command
        public let address: SOCKS5Address
        /// 该请求在缓冲区里占用的字节数；其后剩余字节属于已开始的应用数据，不能丢
        public let consumedBytes: Int
    }

    public struct Datagram {
        public let address: SOCKS5Address
        public let payload: [UInt8]
    }

    // MARK: - 解析

    public static func parseGreeting(_ bytes: [UInt8]) throws -> Greeting? {
        guard bytes.count >= 2 else { return nil }
        guard bytes[0] == SOCKS5.version else { throw SOCKS5Error.unsupportedVersion(bytes[0]) }
        let count = Int(bytes[1])
        guard bytes.count >= 2 + count else { return nil }
        return Greeting(methods: Array(bytes[2..<(2 + count)]))
    }

    public static func parseRequest(_ bytes: [UInt8]) throws -> Request? {
        var cursor = ByteCursor(bytes)
        guard let version = cursor.readUInt8() else { return nil }
        guard version == SOCKS5.version else { throw SOCKS5Error.unsupportedVersion(version) }
        guard let rawCommand = cursor.readUInt8() else { return nil }
        guard let reserved = cursor.readUInt8() else { return nil }
        guard reserved == 0 else { throw SOCKS5Error.badReservedByte(reserved) }
        guard let command = SOCKS5.Command(rawValue: rawCommand) else {
            throw SOCKS5Error.unsupportedCommand(rawCommand)
        }
        guard let address = try parseAddress(&cursor) else { return nil }
        return Request(command: command, address: address, consumedBytes: cursor.index)
    }

    /// 解析 UDP 请求头：RSV(2) FRAG(1) ATYP ADDR PORT，其后全是载荷
    public static func parseDatagram(_ bytes: [UInt8]) throws -> Datagram? {
        var cursor = ByteCursor(bytes)
        guard cursor.readUInt16BE() != nil else { return nil }
        guard let fragment = cursor.readUInt8() else { return nil }
        guard fragment == 0 else { throw SOCKS5Error.fragmentedDatagram(fragment) }
        guard let address = try parseAddress(&cursor) else { return nil }
        return Datagram(address: address, payload: cursor.readRest())
    }

    static func parseAddress(_ cursor: inout ByteCursor) throws -> SOCKS5Address? {
        guard let rawType = cursor.readUInt8() else { return nil }
        guard let type = SOCKS5.AddressType(rawValue: rawType) else {
            throw SOCKS5Error.unsupportedAddressType(rawType)
        }

        let encoded: [UInt8]
        let host: String

        switch type {
        case .ipv4:
            guard let raw = cursor.readBytes(4) else { return nil }
            guard let text = SOCKS5Address.ipv4Text(raw) else {
                throw SOCKS5Error.badAddressValue(ByteCoding.hex(raw))
            }
            encoded = raw
            host = text
        case .ipv6:
            guard let raw = cursor.readBytes(16) else { return nil }
            guard let text = SOCKS5Address.ipv6Text(raw) else {
                throw SOCKS5Error.badAddressValue(ByteCoding.hex(raw))
            }
            encoded = raw
            host = text
        case .domain:
            guard let lengthByte = cursor.readUInt8() else { return nil }
            let length = Int(lengthByte)
            guard length > 0 else { throw SOCKS5Error.domainTooLong(length) }
            guard let raw = cursor.readBytes(length) else { return nil }
            encoded = [lengthByte] + raw
            host = String(decoding: raw, as: UTF8.self)
        }

        guard let port = cursor.readUInt16BE() else { return nil }
        return SOCKS5Address(type: type, host: host, port: port, encoded: encoded)
    }

    // MARK: - 编码

    public static func encodeMethodSelection(_ method: SOCKS5.Method) -> [UInt8] {
        [SOCKS5.version, method.rawValue]
    }

    public static func encodeReply(_ reply: SOCKS5.Reply, address: SOCKS5Address) -> [UInt8] {
        var out: [UInt8] = [SOCKS5.version, reply.rawValue, 0x00]
        out.append(contentsOf: address.wireBytes)
        return out
    }

    public static func encodeDatagram(_ datagram: Datagram) -> [UInt8] {
        var out: [UInt8] = [0x00, 0x00, 0x00] // RSV + FRAG
        out.append(contentsOf: datagram.address.wireBytes)
        out.append(contentsOf: datagram.payload)
        return out
    }
}
