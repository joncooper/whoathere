import Foundation

public let maximumLinuxVzPackageRootRuntimeResultBytesV1 = 256 * 1024 * 1024
public let maximumLinuxVzPackageRootRuntimeEvidenceFrameBytesV1 = 16 * 1024 * 1024

public enum LinuxVzPackageRootRuntimeResultError: Error, Equatable {
  case empty
  case limitExceeded
  case truncated
  case invalidHeader
  case invalidKind
  case invalidDigest
  case invalidSequence
  case invalidSummary
  case nonCanonical
}

public enum LinuxVzPackageRootRuntimeResultFrameKindV1: UInt16, Sendable {
  case transcript = 1
  case supervisor = 2
  case rootReceipt = 3
  case process = 4
  case file = 5
  case network = 6
  case complete = 7
  case error = 8

  fileprivate var maximumPayloadBytes: Int {
    switch self {
    case .transcript: return 512 * 1024
    case .supervisor, .rootReceipt: return 256 * 1024
    case .process, .file, .network:
      return maximumLinuxVzPackageRootRuntimeEvidenceFrameBytesV1
    case .complete, .error: return 64 * 1024
    }
  }
}

public struct LinuxVzPackageRootRuntimeActionEvidenceV1: Equatable, Sendable {
  public let actionIndex: UInt32
  public let supervisor: Data
  public let rootReceipt: Data
  public let process: Data
  public let file: Data
  public let network: Data
}

public struct ParsedLinuxVzPackageRootRuntimeResultV1: Equatable, Sendable {
  public let transcript: Data
  public let transcriptSHA256: String
  public let actions: [LinuxVzPackageRootRuntimeActionEvidenceV1]
  public let summary: Data
  public let summarySHA256: String
  public let executionRequestSHA256: String
  public let executionGrantSHA256: String
  public let attemptBindingSHA256: String
  public let processPlanSHA256: String
  public let artifactSHA256: String
  public let terminal: String
  public let rootEvidenceAuthenticated: Bool
  public let hostCompositionRequired: Bool
  public let authoritativeVerdictPermitted: Bool
  public let publicNetworkRoutePresent: Bool
  public let packageExecution: Bool
  public let syncBackPermitted: Bool
}

public func parseLinuxVzPackageRootRuntimeResultV1(
  _ data: Data
) throws -> ParsedLinuxVzPackageRootRuntimeResultV1 {
  guard !data.isEmpty else { throw LinuxVzPackageRootRuntimeResultError.empty }
  guard data.count <= maximumLinuxVzPackageRootRuntimeResultBytesV1 else {
    throw LinuxVzPackageRootRuntimeResultError.limitExceeded
  }
  var offset = 0
  let transcript = try linuxVzPackageRootRuntimeReadFrameV1(data, offset: &offset)
  guard transcript.kind == .transcript, transcript.actionIndex == 0 else {
    throw LinuxVzPackageRootRuntimeResultError.invalidSequence
  }
  var actions = [LinuxVzPackageRootRuntimeActionEvidenceV1]()
  var summaryFrame: LinuxVzPackageRootRuntimeFrameV1?
  while offset < data.count {
    let frame = try linuxVzPackageRootRuntimeReadFrameV1(data, offset: &offset)
    if frame.kind == .complete {
      guard frame.actionIndex == 0, offset == data.count else {
        throw LinuxVzPackageRootRuntimeResultError.invalidSequence
      }
      summaryFrame = frame
      break
    }
    guard frame.kind == .supervisor, frame.actionIndex > 0,
      actions.last.map({ $0.actionIndex < frame.actionIndex }) ?? true
    else {
      throw LinuxVzPackageRootRuntimeResultError.invalidSequence
    }
    let receipt = try linuxVzPackageRootRuntimeReadFrameV1(data, offset: &offset)
    let process = try linuxVzPackageRootRuntimeReadFrameV1(data, offset: &offset)
    let file = try linuxVzPackageRootRuntimeReadFrameV1(data, offset: &offset)
    let network = try linuxVzPackageRootRuntimeReadFrameV1(data, offset: &offset)
    guard receipt.kind == .rootReceipt,
      process.kind == .process, file.kind == .file, network.kind == .network,
      [receipt, process, file, network].allSatisfy({
        $0.actionIndex == frame.actionIndex
      })
    else {
      throw LinuxVzPackageRootRuntimeResultError.invalidSequence
    }
    actions.append(
      LinuxVzPackageRootRuntimeActionEvidenceV1(
        actionIndex: frame.actionIndex,
        supervisor: frame.payload,
        rootReceipt: receipt.payload,
        process: process.payload,
        file: file.payload,
        network: network.payload
      ))
  }
  guard let summaryFrame, !actions.isEmpty else {
    throw LinuxVzPackageRootRuntimeResultError.invalidSequence
  }
  let summary = try linuxVzPackageRootRuntimeSummaryV1(summaryFrame.payload)
  let actionIndexes = actions.map { String($0.actionIndex) }
  guard summary.schemaVersion == "whoathere.linux_vz_package_root_runtime_result.v1",
    summary.transcriptSHA256 == sha256(transcript.payload),
    summary.processActionIndexes == actionIndexes,
    summary.processActionCount == UInt64(actions.count),
    summary.resultFrameCount == UInt64(2 + actions.count * 5),
    ["complete", "process_failed"].contains(summary.terminal),
    summary.rootEvidenceAuthenticated,
    summary.hostCompositionRequired,
    !summary.authoritativeVerdictPermitted,
    !summary.publicNetworkRoutePresent,
    summary.packageExecution,
    !summary.syncBack
  else {
    throw LinuxVzPackageRootRuntimeResultError.invalidSummary
  }
  return ParsedLinuxVzPackageRootRuntimeResultV1(
    transcript: transcript.payload,
    transcriptSHA256: summary.transcriptSHA256,
    actions: actions,
    summary: summaryFrame.payload,
    summarySHA256: sha256(summaryFrame.payload),
    executionRequestSHA256: summary.executionRequestSHA256,
    executionGrantSHA256: summary.executionGrantSHA256,
    attemptBindingSHA256: summary.attemptBindingSHA256,
    processPlanSHA256: summary.processPlanSHA256,
    artifactSHA256: summary.artifactSHA256,
    terminal: summary.terminal,
    rootEvidenceAuthenticated: true,
    hostCompositionRequired: true,
    authoritativeVerdictPermitted: false,
    publicNetworkRoutePresent: false,
    packageExecution: true,
    syncBackPermitted: false
  )
}

private struct LinuxVzPackageRootRuntimeFrameV1 {
  let kind: LinuxVzPackageRootRuntimeResultFrameKindV1
  let actionIndex: UInt32
  let payload: Data
}

private func linuxVzPackageRootRuntimeReadFrameV1(
  _ data: Data,
  offset: inout Int
) throws -> LinuxVzPackageRootRuntimeFrameV1 {
  let headerBytes = 56
  guard offset <= data.count, data.count - offset >= headerBytes else {
    throw LinuxVzPackageRootRuntimeResultError.truncated
  }
  let header = data[offset..<(offset + headerBytes)]
  guard Data(header.prefix(8)) == Data("WTPKRR01".utf8),
    linuxVzPackageRootRuntimeUInt16V1(header, at: 8) == 1
  else {
    throw LinuxVzPackageRootRuntimeResultError.invalidHeader
  }
  guard
    let kind = LinuxVzPackageRootRuntimeResultFrameKindV1(
      rawValue: linuxVzPackageRootRuntimeUInt16V1(header, at: 10)
    )
  else {
    throw LinuxVzPackageRootRuntimeResultError.invalidKind
  }
  let actionIndex = linuxVzPackageRootRuntimeUInt32V1(header, at: 12)
  let length = linuxVzPackageRootRuntimeUInt64V1(header, at: 16)
  guard length > 0, length <= UInt64(kind.maximumPayloadBytes),
    length <= UInt64(Int.max),
    data.count - offset - headerBytes >= Int(length)
  else {
    throw LinuxVzPackageRootRuntimeResultError.limitExceeded
  }
  let start = offset + headerBytes
  let end = start + Int(length)
  let payload = Data(data[start..<end])
  let expectedDigest = Data(header[(header.startIndex + 24)..<(header.startIndex + 56)])
  guard linuxVzPackageRootRuntimeRawSHA256V1(payload) == expectedDigest else {
    throw LinuxVzPackageRootRuntimeResultError.invalidDigest
  }
  offset = end
  return LinuxVzPackageRootRuntimeFrameV1(
    kind: kind,
    actionIndex: actionIndex,
    payload: payload
  )
}

private struct LinuxVzPackageRootRuntimeSummaryV1 {
  let schemaVersion: String
  let executionRequestSHA256: String
  let executionGrantSHA256: String
  let attemptBindingSHA256: String
  let processPlanSHA256: String
  let artifactSHA256: String
  let transcriptSHA256: String
  let terminal: String
  let processActionIndexes: [String]
  let processActionCount: UInt64
  let resultFrameCount: UInt64
  let rootEvidenceAuthenticated: Bool
  let hostCompositionRequired: Bool
  let authoritativeVerdictPermitted: Bool
  let publicNetworkRoutePresent: Bool
  let packageExecution: Bool
  let syncBack: Bool
}

private func linuxVzPackageRootRuntimeSummaryV1(
  _ data: Data
) throws -> LinuxVzPackageRootRuntimeSummaryV1 {
  guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
    try canonicalJSONData(value) == data,
    Set(value.keys)
      == Set([
        "schema_version", "execution_request_sha256", "execution_grant_sha256",
        "attempt_binding_sha256", "process_plan_sha256", "artifact_sha256",
        "transcript_sha256", "terminal", "process_action_indexes",
        "process_action_count", "result_frame_count", "root_evidence_authenticated",
        "host_composition_required", "authoritative_verdict_permitted",
        "public_network_route_present", "package_execution", "sync_back",
      ]),
    let schemaVersion = value["schema_version"] as? String,
    let executionRequest = value["execution_request_sha256"] as? String,
    let executionGrant = value["execution_grant_sha256"] as? String,
    let attemptBinding = value["attempt_binding_sha256"] as? String,
    let processPlan = value["process_plan_sha256"] as? String,
    let artifact = value["artifact_sha256"] as? String,
    let transcript = value["transcript_sha256"] as? String,
    [executionRequest, executionGrant, attemptBinding, processPlan, artifact, transcript]
      .allSatisfy(linuxVzPackageRootRuntimeDigestV1),
    let terminal = value["terminal"] as? String,
    let indexes = value["process_action_indexes"] as? [String],
    indexes.allSatisfy({ linuxVzPackageRootRuntimeDecimalV1($0).map { $0 > 0 } == true }),
    let actionCount = (value["process_action_count"] as? String)
      .flatMap(linuxVzPackageRootRuntimeDecimalV1),
    let frameCount = (value["result_frame_count"] as? String)
      .flatMap(linuxVzPackageRootRuntimeDecimalV1),
    let authenticated = value["root_evidence_authenticated"] as? Bool,
    let hostComposition = value["host_composition_required"] as? Bool,
    let verdict = value["authoritative_verdict_permitted"] as? Bool,
    let route = value["public_network_route_present"] as? Bool,
    let execution = value["package_execution"] as? Bool,
    let syncBack = value["sync_back"] as? Bool
  else {
    throw LinuxVzPackageRootRuntimeResultError.invalidSummary
  }
  return LinuxVzPackageRootRuntimeSummaryV1(
    schemaVersion: schemaVersion,
    executionRequestSHA256: executionRequest,
    executionGrantSHA256: executionGrant,
    attemptBindingSHA256: attemptBinding,
    processPlanSHA256: processPlan,
    artifactSHA256: artifact,
    transcriptSHA256: transcript,
    terminal: terminal,
    processActionIndexes: indexes,
    processActionCount: actionCount,
    resultFrameCount: frameCount,
    rootEvidenceAuthenticated: authenticated,
    hostCompositionRequired: hostComposition,
    authoritativeVerdictPermitted: verdict,
    publicNetworkRoutePresent: route,
    packageExecution: execution,
    syncBack: syncBack
  )
}

private func linuxVzPackageRootRuntimeUInt16V1(_ bytes: Data.SubSequence, at offset: Int) -> UInt16
{
  bytes[(bytes.startIndex + offset)..<(bytes.startIndex + offset + 2)]
    .reduce(0) { ($0 << 8) | UInt16($1) }
}

private func linuxVzPackageRootRuntimeUInt32V1(_ bytes: Data.SubSequence, at offset: Int) -> UInt32
{
  bytes[(bytes.startIndex + offset)..<(bytes.startIndex + offset + 4)]
    .reduce(0) { ($0 << 8) | UInt32($1) }
}

private func linuxVzPackageRootRuntimeUInt64V1(_ bytes: Data.SubSequence, at offset: Int) -> UInt64
{
  bytes[(bytes.startIndex + offset)..<(bytes.startIndex + offset + 8)]
    .reduce(0) { ($0 << 8) | UInt64($1) }
}

private func linuxVzPackageRootRuntimeRawSHA256V1(_ data: Data) -> Data {
  let text = sha256(data)
  var bytes = Data(capacity: 32)
  var index = text.index(text.startIndex, offsetBy: 7)
  for _ in 0..<32 {
    let next = text.index(index, offsetBy: 2)
    bytes.append(UInt8(text[index..<next], radix: 16)!)
    index = next
  }
  return bytes
}

private func linuxVzPackageRootRuntimeDecimalV1(_ value: String) -> UInt64? {
  guard !value.isEmpty, value == "0" || value.first != "0",
    value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 })
  else { return nil }
  return UInt64(value)
}

private func linuxVzPackageRootRuntimeDigestV1(_ value: String) -> Bool {
  value.utf8.count == 71 && value.hasPrefix("sha256:")
    && value.dropFirst(7).utf8.allSatisfy { byte in
      (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
    }
}
