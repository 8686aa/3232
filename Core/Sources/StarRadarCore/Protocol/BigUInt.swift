import Foundation

/// 极简大端无符号整数，只实现 RawDH 需要的运算。
///
/// 原实现直接用 Python 的任意精度整数做 512 位模幂；iOS 上没有现成的 BN 接口，
/// 这里用 32 位肢体做教材级实现：乘法是竖式，取模走二进制长除法。
/// 取模比 Montgomery 慢一个量级，但一次握手里只跑几百次，实测在几十毫秒量级，
/// 对握手频率完全够用。真嫌慢再把 `modulo` 换成 Montgomery 即可。
public struct BigUInt: Equatable, Comparable, CustomStringConvertible {
    /// 小端序 32 位肢体，最高位肢体保证非零（零只有空数组一种表示）
    private(set) var limbs: [UInt32]

    public static let zero = BigUInt(limbs: [])
    public static let one = BigUInt(1)

    // MARK: - 构造

    init(limbs: [UInt32]) {
        var trimmed = limbs
        while let last = trimmed.last, last == 0 {
            trimmed.removeLast()
        }
        self.limbs = trimmed
    }

    public init(_ value: UInt32) {
        self.init(limbs: value == 0 ? [] : [value])
    }

    public init(_ value: UInt64) {
        self.init(limbs: [UInt32(truncatingIfNeeded: value), UInt32(truncatingIfNeeded: value >> 32)])
    }

    public init(_ value: Int) {
        self.init(UInt64(max(0, value)))
    }

    /// 网络序字节流（前导零会被裁掉）
    public init(bigEndianBytes bytes: [UInt8]) {
        var limbbuffer: [UInt32] = []
        limbbuffer.reserveCapacity(bytes.count / 4 + 1)
        // 从最低字节往上组装
        var index = bytes.count
        while index > 0 {
            let start = max(0, index - 4)
            var limb: UInt32 = 0
            for position in start..<index {
                limb = (limb << 8) | UInt32(bytes[position])
            }
            limbbuffer.append(limb)
            index = start
        }
        self.init(limbs: limbbuffer)
    }

    /// 十六进制字符串，忽略所有前导 `0x` 与空白
    public init?(hex: String) {
        var digits = hex.lowercased()
        if digits.hasPrefix("0x") { digits.removeFirst(2) }
        digits = digits.filter { !$0.isWhitespace }
        guard !digits.isEmpty else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(digits.count / 2 + 1)
        var buffer = digits.startIndex
        // 奇数长度先补一个半字节，保证按字节切分
        if digits.count % 2 == 1 {
            guard let value = UInt8(String(digits[buffer]), radix: 16) else { return nil }
            bytes.append(value)
            buffer = digits.index(after: buffer)
        }
        while buffer < digits.endIndex {
            let next = digits.index(buffer, offsetBy: 2)
            guard let value = UInt8(String(digits[buffer..<next]), radix: 16) else { return nil }
            bytes.append(value)
            buffer = next
        }
        self.init(bigEndianBytes: bytes)
    }

    // MARK: - 查询

    public var isZero: Bool { limbs.isEmpty }

    public var description: String {
        ByteCoding.hex(bigEndianBytes())
    }

    public var bitWidth: Int {
        guard let top = limbs.last else { return 0 }
        return (limbs.count - 1) * 32 + (32 - top.leadingZeroBitCount)
    }

    public func bit(at index: Int) -> Bool {
        guard index >= 0 else { return false }
        let limbIndex = index / 32
        guard limbIndex < limbs.count else { return false }
        let offset = UInt32(index % 32)
        return (limbs[limbIndex] >> offset) & 1 == 1
    }

    /// 最短网络序表示；零返回 `[0x00]`。对应原实现的 `minimal_be`。
    public func bigEndianBytes() -> [UInt8] {
        guard !isZero else { return [0x00] }
        var out: [UInt8] = []
        out.reserveCapacity(limbs.count * 4)
        for index in stride(from: limbs.count - 1, through: 0, by: -1) {
            let limb = limbs[index]
            out.append(UInt8(truncatingIfNeeded: limb >> 24))
            out.append(UInt8(truncatingIfNeeded: limb >> 16))
            out.append(UInt8(truncatingIfNeeded: limb >> 8))
            out.append(UInt8(truncatingIfNeeded: limb))
        }
        return ByteCoding.minimalBigEndian(out)
    }

    /// 定长网络序表示；超出长度返回 nil。对应原实现的 `fixed_be`。
    public func bigEndianBytes(fixedSize size: Int) -> [UInt8]? {
        let minimal = bigEndianBytes()
        guard minimal.count <= size else { return nil }
        return [UInt8](repeating: 0, count: size - minimal.count) + minimal
    }

    // MARK: - 比较

    public static func < (lhs: BigUInt, rhs: BigUInt) -> Bool {
        if lhs.limbs.count != rhs.limbs.count { return lhs.limbs.count < rhs.limbs.count }
        for index in stride(from: lhs.limbs.count - 1, through: 0, by: -1) {
            if lhs.limbs[index] != rhs.limbs[index] {
                return lhs.limbs[index] < rhs.limbs[index]
            }
        }
        return false
    }

    // MARK: - 运算

    /// 左移一位，移位进来的最低位由 `bit` 决定
    private mutating func shiftLeftOne(pulling bit: Bool) {
        var carry: UInt32 = 0
        for index in 0..<limbs.count {
            let next = limbs[index] >> 31
            limbs[index] = (limbs[index] << 1) | carry
            carry = next
        }
        if carry != 0 { limbs.append(carry) }
        if bit {
            if limbs.isEmpty {
                limbs = [1]
            } else {
                limbs[0] |= 1
            }
        }
    }

    /// 就地相减，要求 `self >= other`
    private mutating func subtractInPlace(_ other: BigUInt) {
        var borrow: Int64 = 0
        for index in 0..<limbs.count {
            let rhs = index < other.limbs.count ? Int64(other.limbs[index]) : 0
            var diff = Int64(limbs[index]) - rhs - borrow
            if diff < 0 {
                diff += Int64(1) << 32
                borrow = 1
            } else {
                borrow = 0
            }
            limbs[index] = UInt32(truncatingIfNeeded: diff)
        }
        var trimmed = limbs
        while let last = trimmed.last, last == 0 {
            trimmed.removeLast()
        }
        limbs = trimmed
    }

    public func multiplied(by other: BigUInt) -> BigUInt {
        if isZero || other.isZero { return .zero }
        var result = [UInt32](repeating: 0, count: limbs.count + other.limbs.count)
        for i in 0..<limbs.count {
            var carry: UInt64 = 0
            let left = UInt64(limbs[i])
            for j in 0..<other.limbs.count {
                let index = i + j
                let current = UInt64(result[index]) + left * UInt64(other.limbs[j]) + carry
                result[index] = UInt32(truncatingIfNeeded: current)
                carry = current >> 32
            }
            var index = i + other.limbs.count
            while carry != 0 && index < result.count {
                let current = UInt64(result[index]) + carry
                result[index] = UInt32(truncatingIfNeeded: current)
                carry = current >> 32
                index += 1
            }
        }
        return BigUInt(limbs: result)
    }

    /// 二进制长除法取模。逐位试商，位宽 × 肢体数 的代价。
    public func modulo(_ divisor: BigUInt) -> BigUInt {
        precondition(!divisor.isZero, "除数为零")
        if self < divisor { return self }
        var remainder = BigUInt.zero
        let width = bitWidth
        guard width > 0 else { return .zero }
        for index in stride(from: width - 1, through: 0, by: -1) {
            remainder.shiftLeftOne(pulling: bit(at: index))
            if remainder >= divisor {
                remainder.subtractInPlace(divisor)
            }
        }
        return remainder
    }

    /// 平方乘模幂
    public static func modPow(base: BigUInt, exponent: BigUInt, modulus: BigUInt) -> BigUInt {
        precondition(!modulus.isZero, "模数为零")
        if modulus == BigUInt(1) { return .zero }
        if exponent.isZero { return BigUInt(1).modulo(modulus) }

        var result = BigUInt(1)
        var factor = base.modulo(modulus)
        let width = exponent.bitWidth
        for index in 0..<width {
            if exponent.bit(at: index) {
                result = result.multiplied(by: factor).modulo(modulus)
            }
            if index + 1 < width {
                factor = factor.multiplied(by: factor).modulo(modulus)
            }
        }
        return result
    }
}
