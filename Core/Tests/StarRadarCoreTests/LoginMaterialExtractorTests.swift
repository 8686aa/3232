import XCTest
@testable import StarRadarCore

/// 期望值全部来自 `Temp/verify_login_materials.py` 那份独立参考实现，
/// 参考实现逐条对齐 `pytho/_dis/login_materials.dis.txt` 的字节码 —— 两边是
/// 各自独立写的，对上了才说明读反汇编时没读岔。
final class LoginMaterialExtractorTests: XCTestCase {
    private func records(_ json: String) -> [LoginMaterialRecord] {
        LoginMaterialExtractor.extractFields(Array(json.utf8))
    }

    func testExtractsBase64MaterialFromNamedKey() throws {
        let material = (0..<128).map { UInt8($0) }
        let blob = Data(material).base64EncodedString()
        let found = records("{\"data\":{\"encryptionKey\":\"\(blob)\"}}")

        XCTAssertEqual(found.count, 1)
        let record = try XCTUnwrap(found.first)
        XCTAssertEqual(record.kind, .namedKeyCandidate)
        XCTAssertEqual(record.path, "$.data.encryptionKey")
        XCTAssertEqual(record.payload, material)
        // 这个 sha256 的前 8 字节正是上报报文里的 k，与 SecureWS 黄金向量同源
        XCTAssertEqual(
            record.fingerprint,
            "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5"
        )
    }

    /// 字段名先 lower 再去掉 `_` 才比对，`udp_key` 命中 `udpkey`
    func testExtractsHexKeyWithNormalizedName() throws {
        let key = (0..<32).map { UInt8($0) }
        let found = records("{\"udp_key\":\"\(Hex.encode(key))\"}")

        XCTAssertEqual(found.count, 1)
        XCTAssertEqual(found.first?.path, "$.udp_key")
        XCTAssertEqual(found.first?.payload, key)
        XCTAssertEqual(
            found.first?.fingerprint,
            "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"
        )
    }

    /// `accessInfo` 把 JSON 装在字符串里，要接着递归；
    /// 同时浮点数组和布尔数组都不满足「真整数」，不能当密钥材料
    func testWalksNestedJSONStringAndRejectsFloatAndBoolArrays() throws {
        let modulus = String(repeating: "f", count: 64)
        let inner = "{\"user_id_key\":\"\(modulus)\","
            + "\"dwUdpKeyMethod\":1,\"dwUdpEncMethod\":2}"
        let escaped = inner.replacingOccurrences(of: "\"", with: "\\\"")
        let floats = "[" + Array(repeating: "1.0", count: 32).joined(separator: ",") + "]"
        let bools = "[" + Array(repeating: "true", count: 32).joined(separator: ",") + "]"
        let found = records("{\"accessInfo\":\"\(escaped)\",\"aesKey\":\(floats),\"battleKey\":\(bools)}")

        XCTAssertEqual(found.count, 1)
        let record = try XCTUnwrap(found.first)
        XCTAssertEqual(record.kind, .udpAccessParameters)
        XCTAssertEqual(record.path, "$.accessInfo.json")
        XCTAssertEqual(
            String(decoding: record.payload, as: UTF8.self),
            "{\"dwUdpEncMethod\": 2, \"dwUdpKeyMethod\": 1, \"user_id_key\": \"\(modulus)\"}"
        )
        XCTAssertEqual(
            record.fingerprint,
            "092c488b31470db1214cebd73397239c88f331b3df727423852b95f84e285ca2"
        )
    }

    /// 模数判据：`int(hex,16) > 5` 且为奇数，长度 32…512 字节
    func testRejectsUnusableModulus() {
        let equalFive = String(repeating: "0", count: 63) + "5"
        let even = String(repeating: "f", count: 63) + "e"
        let json = "{\"a\":{\"user_id_key\":\"\(equalFive)\",\"dwUdpKeyMethod\":1,\"dwUdpEncMethod\":2},"
            + "\"b\":{\"user_id_key\":\"\(even)\",\"dwUdpKeyMethod\":1,\"dwUdpEncMethod\":2},"
            + "\"c\":{\"user_id_key\":\"ff\",\"dwUdpKeyMethod\":1,\"dwUdpEncMethod\":2}}"
        XCTAssertTrue(records(json).isEmpty)
    }

    func testUsableModulusBoundaries() {
        XCTAssertTrue(LoginMaterialExtractor.isUsableModulus(String(repeating: "f", count: 64)))
        XCTAssertFalse(
            LoginMaterialExtractor.isUsableModulus(String(repeating: "0", count: 63) + "5"),
            "值正好等于 5"
        )
        XCTAssertFalse(
            LoginMaterialExtractor.isUsableModulus(String(repeating: "f", count: 63) + "e"),
            "偶数"
        )
        XCTAssertFalse(LoginMaterialExtractor.isUsableModulus("ff"), "只有 1 字节")
        XCTAssertFalse(
            LoginMaterialExtractor.isUsableModulus(String(repeating: "f", count: 1026)),
            "超过 512 字节"
        )
    }

    /// 数组形式；同 payload 同 kind 的第二条按 identity 去重，17 字节不合法
    func testArrayKeysDeduplicateByIdentity() throws {
        let values = (0..<16).map(String.init).joined(separator: ",")
        let wrong = (0..<17).map(String.init).joined(separator: ",")
        let found = records(
            "junk{\"sessionKey\":[\(values)],\"AES_KEY\":[\(values)],\"xtea_key\":[\(wrong)]}"
        )

        XCTAssertEqual(found.count, 1, "同 payload 只留先到的一条")
        XCTAssertEqual(found.first?.path, "$.sessionKey")
        XCTAssertEqual(found.first?.payload, (0..<16).map { UInt8($0) })
        XCTAssertEqual(
            found.first?.fingerprint,
            "be45cb2605bf36bebde684841a28f0fd43c69850a3dce5fedba69928ee3a8991"
        )
    }

    /// 字段名不像标识符时路径里退化成 `<field>`，否则路径会被任意字符污染
    func testNonIdentifierFieldNameUsesPlaceholder() throws {
        let blob = Hex.encode((0..<64).map { UInt8($0) })
        let found = records("{\"1bad-name\":{\"key\":\"\(blob)\"}}")

        XCTAssertEqual(found.count, 1)
        XCTAssertEqual(found.first?.path, "$.<field>.key")
        XCTAssertEqual(
            found.first?.fingerprint,
            "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108"
        )
    }

    func testOversizedDocumentIsIgnored() {
        let data = [UInt8](
            repeating: UInt8(ascii: "x"),
            count: LoginMaterialExtractor.maxDocument + 1
        )
        XCTAssertTrue(LoginMaterialExtractor.extractFields(data).isEmpty)
    }

    /// `json.dumps(fields, sort_keys=True)` 默认分隔符带空格、键按码点升序。
    /// 这串字节要进 sha256 当记录指纹，少一个空格就是另一条记录
    func testParameterPayloadMatchesPythonDumpsFormat() {
        let modulus = String(repeating: "a", count: 63) + "f"
        let payload = LoginMaterialExtractor.parameterPayload(modulus: modulus, methods: ["1", "2"])
        XCTAssertEqual(
            String(decoding: payload, as: UTF8.self),
            "{\"dwUdpEncMethod\": 2, \"dwUdpKeyMethod\": 1, \"user_id_key\": \"\(modulus)\"}"
        )
    }

    func testIdentifierRule() {
        XCTAssertTrue(LoginMaterialExtractor.isIdentifier("a"))
        XCTAssertTrue(LoginMaterialExtractor.isIdentifier("_a0"))
        XCTAssertTrue(LoginMaterialExtractor.isIdentifier(String(repeating: "a", count: 64)))
        XCTAssertFalse(LoginMaterialExtractor.isIdentifier(String(repeating: "a", count: 65)))
        XCTAssertFalse(LoginMaterialExtractor.isIdentifier("1abc"))
        XCTAssertFalse(LoginMaterialExtractor.isIdentifier("a-b"))
        XCTAssertFalse(LoginMaterialExtractor.isIdentifier(""))
    }
}
