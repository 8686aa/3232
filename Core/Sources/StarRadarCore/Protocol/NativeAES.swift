import CommonCrypto
import Foundation

public enum NativeAESError: Error, CustomStringConvertible {
    case cryptFailed(Int32)
    case emptyEncryptedBody
    case bodyNotAligned(Int)
    case decryptedBodyTooShort(Int)
    case trailerMissing
    case invalidPadByte(Int)
    case invalidBodySize(Int)
    case invalidKeyLength(Int)

    public var description: String {
        switch self {
        case .cryptFailed(let status): return "CCCrypt 失败，status=\(status)"
        case .emptyEncryptedBody: return "密文为空"
        case .bodyNotAligned(let size): return "密文长度 \(size) 不是 16 的整数倍"
        case .decryptedBodyTooShort(let size): return "解密结果过短：\(size) 字节"
        case .trailerMissing: return "原生尾部标记 tsf4g 不匹配"
        case .invalidPadByte(let pad): return "尾部填充字节非法：\(pad)"
        case .invalidBodySize(let size): return "还原出的报文体长度非法：\(size)"
        case .invalidKeyLength(let size): return "AES 密钥长度非法：\(size)"
        }
    }
}

/// 原生 AES-CBC 翻译层，对应原实现的 `native_pad_len` / `strip_native_body` / `translate_body`。
///
/// 填充方案很特殊：尾部固定 6 字节 = `tsf4g` + 1 字节填充计数，
/// 而填充计数是「含这 6 字节在内」的总填充长度，所以它一定落在 [6, 21] 且
/// `size + pad` 必然是 16 的倍数（已用 Python 逐长度交叉验证）。
/// 也正因为有自定义尾标，这里用 CBC 且不开 PKCS7。
public enum NativeAES {
    public static let blockSize = 16

    /// 给定报文体长度，算出总填充字节数（含 6 字节尾部）
    public static func padLength(for size: Int) -> Int {
        let remainder = size & 15
        return remainder <= 10 ? 16 - remainder : 32 - remainder
    }

    /// 按原生方案补齐报文体
    public static func pad(_ body: [UInt8]) -> [UInt8] {
        let pad = padLength(for: body.count)
        let filler = [UInt8](repeating: 0, count: pad - TGCP.trailerSize)
        return body + filler + TGCP.trailerMarker + [UInt8(pad)]
    }

    /// 校验尾标并还原报文体
    public static func strip(_ plain: [UInt8]) throws -> [UInt8] {
        guard plain.count >= blockSize else {
            throw NativeAESError.decryptedBodyTooShort(plain.count)
        }
        let markerRange = (plain.count - TGCP.trailerSize)..<(plain.count - 1)
        guard Array(plain[markerRange]) == TGCP.trailerMarker else {
            throw NativeAESError.trailerMissing
        }
        let pad = Int(plain[plain.count - 1])
        let size = plain.count - pad
        guard size > 0 else {
            throw NativeAESError.invalidBodySize(size)
        }
        guard padLength(for: size) == pad else {
            throw NativeAESError.invalidPadByte(pad)
        }
        return Array(plain[0..<size])
    }

    /// 原始 CBC 加解密，不做任何填充。
    static func crypt(
        _ data: [UInt8],
        key: [UInt8],
        operation: CCOperation
    ) throws -> [UInt8] {
        guard key.count == kCCKeySizeAES128 || key.count == kCCKeySizeAES192 || key.count == kCCKeySizeAES256 else {
            throw NativeAESError.invalidKeyLength(key.count)
        }
        if data.isEmpty { return [] }

        var out = [UInt8](repeating: 0, count: data.count + blockSize)
        var moved = 0
        let status = out.withUnsafeMutableBufferPointer { outBuffer -> CCCryptorStatus in
            data.withUnsafeBufferPointer { dataBuffer in
                key.withUnsafeBufferPointer { keyBuffer in
                    TGCP.nativeIV.withUnsafeBufferPointer { ivBuffer in
                        CCCrypt(
                            operation,
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0), // CBC，无填充
                            keyBuffer.baseAddress,
                            key.count,
                            ivBuffer.baseAddress,
                            dataBuffer.baseAddress,
                            data.count,
                            outBuffer.baseAddress,
                            outBuffer.count,
                            &moved
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else {
            throw NativeAESError.cryptFailed(Int32(status))
        }
        return Array(out[0..<moved])
    }

    public static func encrypt(_ plain: [UInt8], key: [UInt8]) throws -> [UInt8] {
        try crypt(plain, key: key, operation: CCOperation(kCCEncrypt))
    }

    public static func decrypt(_ cipher: [UInt8], key: [UInt8]) throws -> [UInt8] {
        try crypt(cipher, key: key, operation: CCOperation(kCCDecrypt))
    }

    /// 用 `source` 解出明文，再用 `destination` 把**同一份已填充明文**重新加密。
    ///
    /// 注意重新加密的是解出来的 `padded` 而不是重新填充过的报文 ——
    /// 原实现就是直接 `encrypt(padded)`，重新填充会改变尾部字节导致对端解析失败。
    public static func translate(
        body: [UInt8],
        source: [UInt8],
        destination: [UInt8]
    ) throws -> (cipher: [UInt8], plain: [UInt8]) {
        guard !body.isEmpty else { throw NativeAESError.emptyEncryptedBody }
        guard body.count % blockSize == 0 else { throw NativeAESError.bodyNotAligned(body.count) }
        let padded = try decrypt(body, key: source)
        let plain = try strip(padded)
        let reencrypted = try encrypt(padded, key: destination)
        return (reencrypted, plain)
    }
}
