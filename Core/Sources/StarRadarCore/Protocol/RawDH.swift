import CryptoKit
import Foundation
import Security

/// RawDH 参数与单侧密钥运算。
///
/// 参数与原实现 [tgcp_protocol.py] 一致：512 位素域、生成元 2、
/// 公钥固定 64 字节大端、共享密钥经 `MD5(minimal_be(shared))` 得到 16 字节 AES-128 密钥。
public enum RawDH {
    public static let primeHex =
        "97981e0aade0de72e29cd2789193562547bad2591fb7e59c523923dddecebccae"
        + "49bdcd4b8ec39022b0bd95d4af8fd3cd600919393255c1084c2fd5abb2fede3"

    public static let prime: BigUInt = {
        guard let value = BigUInt(hex: primeHex) else {
            preconditionFailure("RawDH 素数常量无法解析")
        }
        return value
    }()

    /// P - 1。P 是奇数，直接把最低位清零即可，不用实现通用减法。
    public static let primeMinusOne: BigUInt = {
        var bytes = prime.bigEndianBytes()
        bytes[bytes.count - 1] &= 0xFE
        return BigUInt(bigEndianBytes: bytes)
    }()

    public static let generator = BigUInt(2)

    /// 公钥线上长度固定 64 字节
    public static let publicBytes = 64

    /// 私钥指数长度。原实现的取值没有拿到，这里取 256 位随机数 —— 对 512 位域完全够用。
    public static let privateBytes = 32

    /// 对端公钥合法性：必须落在开区间 (1, P-1)
    public static func isPublicValid(_ value: BigUInt) -> Bool {
        value > BigUInt(1) && value < primeMinusOne
    }
}

/// 一次 DH 交换中某一侧的私钥/公钥对。
public struct RawDHSide {
    public let privateExponent: BigUInt
    public let publicValue: BigUInt

    /// 固定 64 字节大端的公钥，可直接写进 TGCP 头扩展
    public var publicBytes: [UInt8] {
        guard let fixed = publicValue.bigEndianBytes(fixedSize: RawDH.publicBytes) else {
            preconditionFailure("RawDH 公钥超出 64 字节")
        }
        return fixed
    }

    /// 随机生成一侧。私钥在 [1, P-2] 内均匀取即可，这里直接取随机字节再取模。
    public static func create() -> RawDHSide {
        var bytes = [UInt8](repeating: 0, count: RawDH.privateBytes)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status != errSecSuccess {
            for index in 0..<bytes.count {
                bytes[index] = UInt8.random(in: 0...255)
            }
        }
        var exponent = BigUInt(bigEndianBytes: bytes).modulo(RawDH.primeMinusOne)
        if exponent < BigUInt(1) {
            exponent = BigUInt(1)
        }
        return RawDHSide(privateExponent: exponent)
    }

    private init(privateExponent: BigUInt) {
        self.privateExponent = privateExponent
        self.publicValue = BigUInt.modPow(
            base: RawDH.generator,
            exponent: privateExponent,
            modulus: RawDH.prime
        )
    }

    /// 用对端公钥算出共享密钥。对应原实现的 `DhSide.derive_key`。
    /// 失败返回 nil，调用方需要拒绝该对端公钥。
    public func deriveKey(peerPublic: BigUInt) -> [UInt8]? {
        guard RawDH.isPublicValid(peerPublic) else { return nil }
        let shared = BigUInt.modPow(
            base: peerPublic,
            exponent: privateExponent,
            modulus: RawDH.prime
        )
        // key = MD5(minimal_be(shared))
        let digest = Insecure.MD5.hash(data: Data(shared.bigEndianBytes()))
        return Array(digest)
    }
}
