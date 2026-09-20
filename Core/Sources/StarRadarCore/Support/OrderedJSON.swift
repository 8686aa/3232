import Foundation

/// 一个 JSON 数值。保留「字面量是否整数」这一信息 —— 提取逻辑要严格区分
/// `int` 与 `float`（等价于 Python 的 `type(x) is int`），布尔值不算整数。
public struct JSONNumber: Equatable {
    public let raw: String
    public let isIntegral: Bool
    /// 仅当是整数且落在 `Int64` 范围内时非 nil。
    public let int64Value: Int64?

    public var intValue: Int? { int64Value.map(Int.init) }
    public var uint64Value: UInt64? { int64Value.flatMap { $0 >= 0 ? UInt64($0) : nil } }
}

public struct JSONMember: Equatable {
    public let key: String
    public let value: JSONValue

    public init(key: String, value: JSONValue) {
        self.key = key
        self.value = value
    }
}

/// 保序 JSON 值。
///
/// 为什么不用 `JSONSerialization`：提取逻辑依赖**键的原始顺序**（按序遍历，
/// 候选表最多留 32 条、先到先得），而 `NSDictionary` 的遍历顺序未定义；
/// 另外它把 `true/false` 也交成 `NSNumber`，`as? Int` 能通过，会让
/// 「整数」判断失真。这里只实现协议用到的那点语法，自己解更可控。
public indirect enum JSONValue: Equatable {
    case object([JSONMember])
    case array([JSONValue])
    case string(String)
    case number(JSONNumber)
    case bool(Bool)
    case null

    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    public var boolValue: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }

    public var intValue: Int? {
        if case .number(let value) = self { return value.intValue }
        return nil
    }

    public var uint64Value: UInt64? {
        if case .number(let value) = self { return value.uint64Value }
        return nil
    }

    public var members: [JSONMember]? {
        if case .object(let value) = self { return value }
        return nil
    }

    public var elements: [JSONValue]? {
        if case .array(let value) = self { return value }
        return nil
    }

    /// 按键取值，非对象返回 nil。解析器对重复键原位覆盖，所以同名成员至多一个。
    public subscript(key: String) -> JSONValue? {
        guard case .object(let members) = self else { return nil }
        return members.first(where: { $0.key == key })?.value
    }

    /// 解析成字典（重复键后者覆盖前者，与 Python dict 一致）。
    public static func parseObject(_ text: String) -> [String: JSONValue]? {
        guard let value = JSONParser.parse(text), let members = value.members else { return nil }
        var out: [String: JSONValue] = [:]
        for member in members { out[member.key] = member.value }
        return out
    }
}

public enum JSONSyntax: Error {
    case unexpectedEnd
    case tooDeep
    case invalidUTF8
    case invalidEscape
    case controlCharacter
    case invalidNumber
    case expectedKey
    case expectedColon
    case expectedSeparator
}

/// 最小递归下降 JSON 解析器。
///
/// 与 `JSONSerialization` 相比多出两点能力，缺一不可：
/// - `parseValue(in:from:)` 从任意字节偏移解**一个**值，对应 Python 的
///   `JSONDecoder.raw_decode`（登录明文里常常是「一段垃圾 + 一个 JSON + 一段垃圾」）；
/// - 对象保序。
public enum JSONParser {
    /// 嵌套深度上限。载荷是攻击面，必须有界。
    static let maxDepth = 64

    public static func parse(_ text: String) -> JSONValue? {
        let bytes = Array(text.utf8)
        var reader = Reader(bytes: bytes, index: 0)
        guard let value = try? reader.parseValue(depth: 0) else { return nil }
        reader.skipWhitespace()
        guard reader.index == bytes.count else { return nil }
        return value
    }

    /// 从 `offset` 起解一个完整值，返回（值，结束偏移）。调用方失败时 +1 继续试探。
    public static func parseValue(
        in bytes: [UInt8],
        from offset: Int
    ) -> (value: JSONValue, end: Int)? {
        guard offset >= 0, offset < bytes.count else { return nil }
        var reader = Reader(bytes: bytes, index: offset)
        guard let value = try? reader.parseValue(depth: 0) else { return nil }
        return (value, reader.index)
    }

    private struct Reader {
        let bytes: [UInt8]
        var index: Int

        mutating func skipWhitespace() {
            while index < bytes.count {
                switch bytes[index] {
                case 0x20, 0x09, 0x0A, 0x0D: index += 1
                default: return
                }
            }
        }

        mutating func parseValue(depth: Int) throws -> JSONValue {
            guard depth <= JSONParser.maxDepth else { throw JSONSyntax.tooDeep }
            skipWhitespace()
            guard index < bytes.count else { throw JSONSyntax.unexpectedEnd }
            switch bytes[index] {
            case UInt8(ascii: "{"): return .object(try parseObject(depth: depth))
            case UInt8(ascii: "["): return .array(try parseArray(depth: depth))
            case UInt8(ascii: "\""): return .string(try parseString())
            case UInt8(ascii: "t"): try expect("true"); return .bool(true)
            case UInt8(ascii: "f"): try expect("false"); return .bool(false)
            case UInt8(ascii: "n"): try expect("null"); return .null
            default: return .number(try parseNumber())
            }
        }

        private mutating func expect(_ literal: String) throws {
            let expected = Array(literal.utf8)
            guard index + expected.count <= bytes.count else { throw JSONSyntax.unexpectedEnd }
            guard Array(bytes[index..<(index + expected.count)]) == expected else {
                throw JSONSyntax.invalidNumber
            }
            index += expected.count
        }

        private mutating func parseObject(depth: Int) throws -> [JSONMember] {
            index += 1 // '{'
            var members: [JSONMember] = []
            skipWhitespace()
            if index < bytes.count, bytes[index] == UInt8(ascii: "}") {
                index += 1
                return members
            }
            while true {
                skipWhitespace()
                guard index < bytes.count, bytes[index] == UInt8(ascii: "\"") else {
                    throw JSONSyntax.expectedKey
                }
                let key = try parseString()
                skipWhitespace()
                guard index < bytes.count, bytes[index] == UInt8(ascii: ":") else {
                    throw JSONSyntax.expectedColon
                }
                index += 1
                let value = try parseValue(depth: depth + 1)
                // 重复键覆盖值但保留原位置，与 Python dict 的语义一致
                if let existing = members.firstIndex(where: { $0.key == key }) {
                    members[existing] = JSONMember(key: key, value: value)
                } else {
                    members.append(JSONMember(key: key, value: value))
                }
                skipWhitespace()
                guard index < bytes.count else { throw JSONSyntax.unexpectedEnd }
                if bytes[index] == UInt8(ascii: ",") {
                    index += 1
                    continue
                }
                if bytes[index] == UInt8(ascii: "}") {
                    index += 1
                    return members
                }
                throw JSONSyntax.expectedSeparator
            }
        }

        private mutating func parseArray(depth: Int) throws -> [JSONValue] {
            index += 1 // '['
            var elements: [JSONValue] = []
            skipWhitespace()
            if index < bytes.count, bytes[index] == UInt8(ascii: "]") {
                index += 1
                return elements
            }
            while true {
                elements.append(try parseValue(depth: depth + 1))
                skipWhitespace()
                guard index < bytes.count else { throw JSONSyntax.unexpectedEnd }
                if bytes[index] == UInt8(ascii: ",") {
                    index += 1
                    continue
                }
                if bytes[index] == UInt8(ascii: "]") {
                    index += 1
                    return elements
                }
                throw JSONSyntax.expectedSeparator
            }
        }

        private mutating func parseString() throws -> String {
            index += 1 // '"'
            var utf8: [UInt8] = []
            while index < bytes.count {
                let byte = bytes[index]
                if byte == UInt8(ascii: "\"") {
                    index += 1
                    guard let text = String(bytes: utf8, encoding: .utf8) else {
                        throw JSONSyntax.invalidUTF8
                    }
                    return text
                }
                guard byte == UInt8(ascii: "\\") else {
                    if byte < 0x20 { throw JSONSyntax.controlCharacter }
                    utf8.append(byte)
                    index += 1
                    continue
                }
                index += 1
                guard index < bytes.count else { throw JSONSyntax.unexpectedEnd }
                switch bytes[index] {
                case UInt8(ascii: "\""): utf8.append(UInt8(ascii: "\"")); index += 1
                case UInt8(ascii: "\\"): utf8.append(UInt8(ascii: "\\")); index += 1
                case UInt8(ascii: "/"): utf8.append(UInt8(ascii: "/")); index += 1
                case UInt8(ascii: "b"): utf8.append(0x08); index += 1
                case UInt8(ascii: "f"): utf8.append(0x0C); index += 1
                case UInt8(ascii: "n"): utf8.append(0x0A); index += 1
                case UInt8(ascii: "r"): utf8.append(0x0D); index += 1
                case UInt8(ascii: "t"): utf8.append(0x09); index += 1
                case UInt8(ascii: "u"):
                    index += 1
                    utf8.append(contentsOf: try parseUnicodeEscape())
                default:
                    throw JSONSyntax.invalidEscape
                }
            }
            throw JSONSyntax.unexpectedEnd
        }

        /// 处理 `\uXXXX`，含 UTF-16 代理对（密文里出现非 BMP 字符时必踩）。
        private mutating func parseUnicodeEscape() throws -> [UInt8] {
            let first = try parseHex4()
            var scalarValue = UInt32(first)
            if (0xD800...0xDBFF).contains(first) {
                guard index + 1 < bytes.count,
                      bytes[index] == UInt8(ascii: "\\"),
                      bytes[index + 1] == UInt8(ascii: "u") else {
                    throw JSONSyntax.invalidEscape
                }
                index += 2
                let second = try parseHex4()
                guard (0xDC00...0xDFFF).contains(second) else { throw JSONSyntax.invalidEscape }
                scalarValue = 0x10000
                    + (UInt32(first) - 0xD800) << 10
                    + (UInt32(second) - 0xDC00)
            } else if (0xDC00...0xDFFF).contains(first) {
                throw JSONSyntax.invalidEscape
            }
            guard let scalar = Unicode.Scalar(scalarValue) else { throw JSONSyntax.invalidEscape }
            return Array(String(scalar).utf8)
        }

        private mutating func parseHex4() throws -> UInt16 {
            guard index + 4 <= bytes.count else { throw JSONSyntax.unexpectedEnd }
            var value: UInt16 = 0
            for _ in 0..<4 {
                guard let digit = Hex.value(of: bytes[index]) else { throw JSONSyntax.invalidEscape }
                value = (value << 4) | UInt16(digit)
                index += 1
            }
            return value
        }

        private mutating func parseNumber() throws -> JSONNumber {
            let start = index
            if index < bytes.count, bytes[index] == UInt8(ascii: "-") { index += 1 }
            var integral = true
            var digits = 0
            while index < bytes.count {
                let byte = bytes[index]
                if byte >= 0x30 && byte <= 0x39 {
                    digits += 1
                    index += 1
                    continue
                }
                if byte == UInt8(ascii: ".") {
                    integral = false
                    index += 1
                    continue
                }
                if byte == UInt8(ascii: "e") || byte == UInt8(ascii: "E") {
                    integral = false
                    index += 1
                    if index < bytes.count,
                       bytes[index] == UInt8(ascii: "+") || bytes[index] == UInt8(ascii: "-") {
                        index += 1
                    }
                    continue
                }
                break
            }
            guard digits > 0 else { throw JSONSyntax.invalidNumber }
            let raw = String(decoding: bytes[start..<index], as: UTF8.self)
            return JSONNumber(
                raw: raw,
                isIntegral: integral,
                int64Value: integral ? Int64(raw) : nil
            )
        }
    }
}
