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
    let sectionRange = (beginIndex + 1)..<endIndex
    let encodedFragments = sectionRange.compactMap { lineIndex in
        linuxVzPackageExecutionBase64FragmentV1(lines[lineIndex]).map {
            LinuxVzPackageExecutionIndexedBase64FragmentV1(
                lineIndex: lineIndex,
                value: $0
            )
        }
    }
    let encoded = encodedFragments.map(\.value).joined()
    do {
        return try linuxVzPackageExecutionValidateBase64SectionV1(
            encoded,
            byteLength: byteLength,
            digest: digest,
            maximumBytes: maximumBytes
        )
    } catch let originalError as LinuxVzPackageExecutionSerialEvidenceError {
        if let recovered = linuxVzPackageExecutionRecoverBase64SectionV1(
            lines,
            sectionRange: sectionRange,
            acceptedFragments: encodedFragments,
            byteLength: byteLength,
            digest: digest,
            maximumBytes: maximumBytes
        ) {
            return recovered
        }
        throw originalError
    }
}

private struct LinuxVzPackageExecutionIndexedBase64FragmentV1 {
    let lineIndex: Int
    let value: String
}

private struct LinuxVzPackageExecutionRecoveryBase64FragmentV1 {
    let lineIndex: Int
    let value: String
}

private let linuxVzPackageExecutionBase64LineBytesV1 = 76
private let maximumLinuxVzPackageExecutionRecoveryEncodedBytesV1 = 32 * 1024 * 1024
private let maximumLinuxVzPackageExecutionRecoveryRejectedLinesV1 = 1024
private let maximumLinuxVzPackageExecutionRecoveryLineBytesV1 = 4096
private let maximumLinuxVzPackageExecutionRecoveryCandidateLinesV1 = 4
private let maximumLinuxVzPackageExecutionRecoveryCandidatesV1 = 16

private func linuxVzPackageExecutionValidateBase64SectionV1(
    _ encoded: String,
    byteLength: UInt64,
    digest: String,
    maximumBytes: Int
) throws -> Data {
    guard !encoded.isEmpty,
          let decoded = Data(base64Encoded: encoded),
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

private func linuxVzPackageExecutionRecoverBase64SectionV1(
    _ lines: [String],
    sectionRange: Range<Int>,
    acceptedFragments: [LinuxVzPackageExecutionIndexedBase64FragmentV1],
    byteLength: UInt64,
    digest: String,
    maximumBytes: Int
) -> Data? {
    // Recovery is deliberately limited to the observed failure mode: one normal
    // 76-character serial fragment was embedded in a noisy console line. The
    // terminal byte length and digest remain the sole authority for accepting it.
    guard !acceptedFragments.isEmpty else { return nil }
    let encodedByteCount = acceptedFragments.reduce(into: 0) { count, fragment in
        count += fragment.value.utf8.count
    }
    let expectedEncodedByteCount = ((Int(byteLength) + 2) / 3) * 4
    guard expectedEncodedByteCount <= maximumLinuxVzPackageExecutionRecoveryEncodedBytesV1,
          encodedByteCount + linuxVzPackageExecutionBase64LineBytesV1
              == expectedEncodedByteCount,
          let candidates = linuxVzPackageExecutionRecoveryCandidatesV1(
              lines,
              sectionRange: sectionRange
          ),
          !candidates.isEmpty else {
        return nil
    }

    var authenticated: Data?
    for candidate in candidates {
        var fragments = [String]()
        fragments.reserveCapacity(acceptedFragments.count + 1)
        var inserted = false
        for fragment in acceptedFragments {
            if !inserted, candidate.lineIndex < fragment.lineIndex {
                fragments.append(candidate.value)
                inserted = true
            }
            fragments.append(fragment.value)
        }
        if !inserted {
            fragments.append(candidate.value)
        }
        guard let decoded = try? linuxVzPackageExecutionValidateBase64SectionV1(
            fragments.joined(),
            byteLength: byteLength,
            digest: digest,
            maximumBytes: maximumBytes
        ) else {
            continue
        }
        // Even two paths that reconstruct identical bytes are ambiguous evidence:
        // the parser cannot prove which serial position supplied the missing line.
        guard authenticated == nil else { return nil }
        authenticated = decoded
    }
    return authenticated
}

private func linuxVzPackageExecutionRecoveryCandidatesV1(
    _ lines: [String],
    sectionRange: Range<Int>
) -> [LinuxVzPackageExecutionRecoveryBase64FragmentV1]? {
    var candidates = [LinuxVzPackageExecutionRecoveryBase64FragmentV1]()
    var rejectedLineCount = 0
    var candidateLineCount = 0
    for lineIndex in sectionRange {
        let line = lines[lineIndex]
        guard linuxVzPackageExecutionBase64FragmentV1(line) == nil else { continue }
        rejectedLineCount += 1
        guard rejectedLineCount <= maximumLinuxVzPackageExecutionRecoveryRejectedLinesV1,
              line.utf8.count <= maximumLinuxVzPackageExecutionRecoveryLineBytesV1 else {
            return nil
        }
        guard let fragments = linuxVzPackageExecutionBase64WindowsV1(line) else {
            return nil
        }
        if !fragments.isEmpty {
            candidateLineCount += 1
            guard candidateLineCount <= maximumLinuxVzPackageExecutionRecoveryCandidateLinesV1
            else {
                return nil
            }
        }
        guard candidates.count + fragments.count
            <= maximumLinuxVzPackageExecutionRecoveryCandidatesV1
        else {
            return nil
        }
        candidates.append(
            contentsOf: fragments.map {
                LinuxVzPackageExecutionRecoveryBase64FragmentV1(
                    lineIndex: lineIndex,
                    value: $0
                )
            }
        )
    }
    return candidates
}

private func linuxVzPackageExecutionBase64WindowsV1(_ line: String) -> [String]? {
    let bytes = Array(line.utf8)
    var fragments = [String]()
    var runStart = 0
    while runStart < bytes.count {
        while runStart < bytes.count,
              !linuxVzPackageExecutionBase64ByteV1(bytes[runStart]) {
            runStart += 1
        }
        var runEnd = runStart
        while runEnd < bytes.count, linuxVzPackageExecutionBase64ByteV1(bytes[runEnd]) {
            runEnd += 1
        }
        if runEnd - runStart >= linuxVzPackageExecutionBase64LineBytesV1 {
            let windowCount = runEnd - runStart - linuxVzPackageExecutionBase64LineBytesV1 + 1
            guard fragments.count + windowCount
                <= maximumLinuxVzPackageExecutionRecoveryCandidatesV1
            else {
                return nil
            }
            for offset in 0..<windowCount {
                let start = runStart + offset
                let end = start + linuxVzPackageExecutionBase64LineBytesV1
                fragments.append(String(decoding: bytes[start..<end], as: UTF8.self))
            }
        }
        runStart = runEnd + 1
    }
    return fragments
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
        let suffix = bytes.suffix(76)
        let prefix = bytes.dropLast(76)
        guard bytes.count > 76, suffix.count == 76,
              suffix.allSatisfy(linuxVzPackageExecutionBase64ByteV1),
              prefix.contains(where: { !linuxVzPackageExecutionBase64ByteV1($0) })
        else {
            return nil
        }
        return String(decoding: suffix, as: UTF8.self)
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
