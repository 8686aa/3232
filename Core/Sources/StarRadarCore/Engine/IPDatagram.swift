import Foundation

/// 把「四元组 + UDP 载荷」拼回一个完整 IPv4 数据报。
///
/// SOCKS5 中继只在 `onDatagram` 里交出四元组与载荷，原始字节在那之前就丢了，
/// 所以头部里的 TTL / 标识 / 校验和只能按常规值重算；**载荷逐字节一致**，
/// Wireshark 打开与喂给服务端解码器都不受影响。
public enum IPDatagram {
    public static let protocolUDP: UInt8 = 17
    /// IPv4 头长度，无选项
    public static let headerBytes = 20
    public static let udpHeaderBytes = 8
    /// 界面与日志里显示的「报文长度」按 IPv4 + UDP 头算
    public static let ipUDPHeaderBytes = headerBytes + udpHeaderBytes

    /// 组装。远端不是 IPv4（域名、IPv6）时拼不出来，返回 nil —— 上报通道传的就是
    /// IPv4 数据报本身，拿不到地址就没法继续。
    public static func make(
        src: String,
        dst: String,
        sport: UInt16,
        dport: UInt16,
        payload: [UInt8]
    ) -> [UInt8]? {
        guard let srcRaw = SOCKS5Address.ipv4Bytes(src),
              let dstRaw = SOCKS5Address.ipv4Bytes(dst) else { return nil }
        let udpLength = udpHeaderBytes + payload.count
        guard udpLength <= Int(UInt16.max) else { return nil }

        var udp: [UInt8] = []
        udp.reserveCapacity(udpLength)
        ByteCoding.appendUInt16BE(sport, to: &udp)
        ByteCoding.appendUInt16BE(dport, to: &udp)
        ByteCoding.appendUInt16BE(UInt16(udpLength), to: &udp)
        ByteCoding.appendUInt16BE(0, to: &udp) // 校验和先占位
        udp.append(contentsOf: payload)

        // UDP 校验和带伪首部：源/目的地址 + 0 + 协议号 + UDP 长度
        var pseudo = srcRaw + dstRaw
        pseudo.append(contentsOf: [0, protocolUDP])
        ByteCoding.appendUInt16BE(UInt16(udpLength), to: &pseudo)
        ByteCoding.writeUInt16BE(checksum(pseudo + udp), into: &udp, at: 6)

        let total = headerBytes + udpLength
        var header: [UInt8] = [
            0x45, 0, // 版本 4 + 头长 5；DSCP/ECN 全 0
            UInt8(truncatingIfNeeded: total >> 8), UInt8(truncatingIfNeeded: total),
            0, 0, // 标识：镜像报文用不到，恒 0
            0, 0, // 标志 + 片偏移：不分片
            64, protocolUDP, // TTL 与协议号
            0, 0, // 头校验和先占位
        ]
        header.append(contentsOf: srcRaw)
        header.append(contentsOf: dstRaw)
        ByteCoding.writeUInt16BE(checksum(header), into: &header, at: 10)
        return header + udp
    }

    /// RFC 1071 反码求和。奇数长度按尾部补一个 0 字节处理。
    public static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var index = 0
        while index + 1 < bytes.count {
            sum += UInt32(bytes[index]) << 8 | UInt32(bytes[index + 1])
            index += 2
        }
        if index < bytes.count { sum += UInt32(bytes[index]) << 8 }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return UInt16(~sum & 0xFFFF)
    }
}
