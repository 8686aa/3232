import Compression
import Foundation

enum LZ4BlockError: Error, CustomStringConvertible {
    case decompressFailed(Int)

    var description: String {
        switch self {
        case .decompressFailed(let size): return "LZ4 块解压失败，输入 \(size) 字节"
        }
    }
}

/// 只做 raw LZ4 块解压，对应 Python 侧 `lz4.block.decompress`。
/// 用系统 Compression 框架的 `COMPRESSION_LZ4_RAW`，不引第三方依赖。
enum LZ4Block {
    /// 输出缓冲从 64KB 起翻倍重试，直到成功或超过上限。
    /// `compression_decode_buffer` 在缓冲不足时返回 0，只能靠重试区分「缓冲不够」和「数据非法」。
    static func decompress(_ data: [UInt8], maxSize: Int) throws -> [UInt8] {
        guard !data.isEmpty else { throw LZ4BlockError.decompressFailed(0) }

        var capacity = min(64 * 1024, maxSize)
        while capacity <= maxSize {
            var destination = [UInt8](repeating: 0, count: capacity)
            let written = data.withUnsafeBufferPointer { source -> Int in
                guard let sourceBase = source.baseAddress else { return 0 }
                return destination.withUnsafeMutableBufferPointer { sink -> Int in
                    guard let sinkBase = sink.baseAddress else { return 0 }
                    return compression_decode_buffer(
                        sinkBase,
                        sink.count,
                        sourceBase,
                        source.count,
                        nil,
                        COMPRESSION_LZ4_RAW
                    )
                }
            }
            if written > 0 {
                return Array(destination[0..<written])
            }
            if capacity == maxSize { break }
            capacity = min(capacity * 2, maxSize)
        }
        throw LZ4BlockError.decompressFailed(data.count)
    }
}
