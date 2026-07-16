import Foundation

public let maximumLinuxVzPackageExecutionSerialBytesV1 = 384 * 1024 * 1024
public let maximumLinuxVzPackageExecutionResultBytesV1 = 256 * 1024 * 1024
public let maximumLinuxVzPackageExecutionChildLogBytesV1 = 1024 * 1024

public enum LinuxVzPackageExecutionSerialEvidenceError: Error, Equatable {
    case empty
    case limitExceeded
    case missingTerminal
    case malformedSection
    case invalidBase64
    case digestMismatch
    case lengthMismatch
}

public struct ParsedLinuxVzPackageExecutionSerialEvidenceV1: Equatable, Sendable {
    public let result: Data
    public let resultSHA256: String
    public let childLog: Data?
    public let childLogSHA256: String?
    public let guestExecutionComplete: Bool
    public let guestFailureReason: String?
    public let publicNetworkRoutePresent: Bool
    public let syncBackPermitted: Bool
}

public func parseLinuxVzPackageExecutionSerialEvidenceV1(
    _ serialData: Data
) throws -> ParsedLinuxVzPackageExecutionSerialEvidenceV1 {
    guard !serialData.isEmpty else {
        throw LinuxVzPackageExecutionSerialEvidenceError.empty
    }
    guard serialData.count <= maximumLinuxVzPackageExecutionSerialBytesV1 else {
        throw LinuxVzPackageExecutionSerialEvidenceError.limitExceeded
    }
    let lines = try linuxVzPackageExecutionSerialLinesV1(serialData)
    let commonRequired = Set([
        "WHOATHERE_PACKAGE_EXECUTION_BEGIN",
        "WHOATHERE_CAPABILITY signed_execution_inputs=verified_exact",
        "WHOATHERE_CAPABILITY rootfs=verified_exact_read_only",
        "WHOATHERE_CAPABILITY external_route_configured=false",
    ])
    guard commonRequired.isSubset(of: Set(lines)) else {
        throw LinuxVzPackageExecutionSerialEvidenceError.missingTerminal
    }
    let succeeded = lines.filter { $0 == "WHOATHERE_PACKAGE_EXECUTION_OK" }
    let failures = lines.filter { $0.hasPrefix("WHOATHERE_PACKAGE_EXECUTION_FAILED reason=") }
    guard succeeded.count + failures.count == 1 else {
        throw LinuxVzPackageExecutionSerialEvidenceError.missingTerminal
    }
    let guestExecutionComplete = succeeded.count == 1
    if guestExecutionComplete {
        guard Set([
            "WHOATHERE_CAPABILITY package_execution=true",
            "WHOATHERE_CAPABILITY external_route_configured=false",
            "WHOATHERE_CAPABILITY sync_back=false",
        ]).isSubset(of: Set(lines)) else {
            throw LinuxVzPackageExecutionSerialEvidenceError.missingTerminal
        }
    }
    let completeResult = try linuxVzPackageExecutionBase64SectionV1(
        lines,
        marker: "WHOATHERE_PACKAGE_EXECUTION_RESULT_BASE64",
        maximumBytes: maximumLinuxVzPackageExecutionResultBytesV1,
        required: false
    )
    let partialResult = try linuxVzPackageExecutionBase64SectionV1(
        lines,
        marker: "WHOATHERE_PACKAGE_EXECUTION_PARTIAL_RESULT_BASE64",
        maximumBytes: maximumLinuxVzPackageExecutionResultBytesV1,
        required: false
    )
    guard (completeResult == nil) != (partialResult == nil),
          let result = completeResult ?? partialResult,
          guestExecutionComplete == (completeResult != nil) else {
        throw LinuxVzPackageExecutionSerialEvidenceError.malformedSection
    }
    let child = try linuxVzPackageExecutionBase64SectionV1(
        lines,
        marker: "WHOATHERE_PACKAGE_EXECUTION_CHILD_LOG_BASE64",
        maximumBytes: maximumLinuxVzPackageExecutionChildLogBytesV1,
        required: false
    )
    return ParsedLinuxVzPackageExecutionSerialEvidenceV1(
        result: result,
        resultSHA256: sha256(result),
        childLog: child,
        childLogSHA256: child.map(sha256),
        guestExecutionComplete: guestExecutionComplete,
        guestFailureReason: failures.first.map {
            String($0.dropFirst("WHOATHERE_PACKAGE_EXECUTION_FAILED reason=".count))
        },
        publicNetworkRoutePresent: false,
        syncBackPermitted: false
    )
}

private func linuxVzPackageExecutionSerialLinesV1(_ data: Data) throws -> [String] {
    guard let text = String(data: data, encoding: .utf8) else {
        throw LinuxVzPackageExecutionSerialEvidenceError.malformedSection
    }
    let normalized = text
        .replacingOccurrences(of: "\r\n", with: "\n")
        .replacingOccurrences(of: "\r", with: "\n")
    return normalized.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
}

private func linuxVzPackageExecutionBase64SectionV1(
    _ lines: [String],
    marker: String,
    maximumBytes: Int,
    required: Bool
) throws -> Data? {
    let begin = "\(marker)_BEGIN"
    let endPrefix = "\(marker)_END sha256="
    let beginIndexes = lines.indices.filter { lines[$0] == begin }
    let endIndexes = lines.indices.filter { lines[$0].hasPrefix(endPrefix) }
    if beginIndexes.isEmpty, endIndexes.isEmpty, !required { return nil }
    guard beginIndexes.count == 1, endIndexes.count == 1,
          let beginIndex = beginIndexes.first, let endIndex = endIndexes.first,
          endIndex > beginIndex + 0 else {
        throw LinuxVzPackageExecutionSerialEvidenceError.malformedSection
    }
    let end = lines[endIndex]
    let suffix = end.dropFirst(endPrefix.count)
    let pieces = suffix.split(separator: " ", omittingEmptySubsequences: false)
    guard pieces.count == 2,
          let digest = pieces.first.map(String.init),
          let lengthField = pieces.last,
          lengthField.hasPrefix("byte_length="),
          let byteLength = linuxVzPackageExecutionDecimalV1(
              String(lengthField.dropFirst("byte_length=".count))
          ),
          byteLength > 0, byteLength <= UInt64(maximumBytes),
          linuxVzPackageExecutionDigestV1(digest) else {
        throw LinuxVzPackageExecutionSerialEvidenceError.malformedSection
    }
    let encodedLines = lines[(beginIndex + 1)..<endIndex].compactMap(
        linuxVzPackageExecutionBase64FragmentV1
    )
    guard !encodedLines.isEmpty,
          let decoded = Data(base64Encoded: encodedLines.joined()),
          decoded.count <= maximumBytes else {
        throw LinuxVzPackageExecutionSerialEvidenceError.invalidBase64
    }
    guard decoded.count == Int(byteLength) else {
        throw LinuxVzPackageExecutionSerialEvidenceError.lengthMismatch
    }
    guard sha256(decoded) == digest else {
        throw LinuxVzPackageExecutionSerialEvidenceError.digestMismatch
    }
    return decoded
}

private func linuxVzPackageExecutionBase64FragmentV1(_ line: String) -> String? {
    let bytes = line.utf8
    if !bytes.isEmpty, bytes.count <= 76,
       bytes.allSatisfy(linuxVzPackageExecutionBase64ByteV1) {
        return line
    }
    let prefix = bytes.prefix(76)
    guard bytes.count > 76, prefix.count == 76,
          prefix.allSatisfy(linuxVzPackageExecutionBase64ByteV1),
          bytes.dropFirst(76).first.map({ !linuxVzPackageExecutionBase64ByteV1($0) }) == true
    else {
        return nil
    }
    return String(decoding: prefix, as: UTF8.self)
}

private func linuxVzPackageExecutionBase64ByteV1(_ byte: UInt8) -> Bool {
    (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
        || (byte >= 48 && byte <= 57) || byte == 43 || byte == 47 || byte == 61
}

private func linuxVzPackageExecutionDecimalV1(_ value: String) -> UInt64? {
    guard !value.isEmpty, value == "0" || value.first != "0",
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return nil }
    return UInt64(value)
}

private func linuxVzPackageExecutionDigestV1(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
        }
}
