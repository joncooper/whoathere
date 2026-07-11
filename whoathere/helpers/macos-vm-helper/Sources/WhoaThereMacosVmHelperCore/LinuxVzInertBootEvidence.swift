import Foundation

public let linuxVzInertSuccessMarkerV1 = "WHOATHERE_LINUX_VZ_INERT_OK"

public let linuxVzInertRequiredCapabilityMarkersV1 = [
    "WHOATHERE_CAPABILITY kernel_release=6.18.35-0-virt",
    "WHOATHERE_CAPABILITY architecture=aarch64",
    "WHOATHERE_CAPABILITY kernel_btf=present",
    "WHOATHERE_CAPABILITY cgroup_v2=mounted",
    "WHOATHERE_CAPABILITY bpf_fs=mounted",
    "WHOATHERE_CAPABILITY fanotify_init=available",
    "WHOATHERE_CAPABILITY bpf_program_load=available",
    "WHOATHERE_CAPABILITY syscall_probe=passed",
    "WHOATHERE_CAPABILITY virtio_net=loaded",
    "WHOATHERE_CAPABILITY external_route_configured=false",
    "WHOATHERE_CAPABILITY package_execution=false",
    "WHOATHERE_CAPABILITY sync_back=false",
]

public func linuxVzInertSerialContainsExactMarker(_ serialData: Data, marker: String) -> Bool {
    linuxVzInertSerialLines(serialData).contains(marker)
}

public func linuxVzInertMissingCapabilityMarkers(_ serialData: Data) -> [String] {
    let lines = linuxVzInertSerialLines(serialData)
    return linuxVzInertRequiredCapabilityMarkersV1.filter { !lines.contains($0) }
}

private func linuxVzInertSerialLines(_ serialData: Data) -> Set<String> {
    Set(serialData.split(separator: 0x0A).map { line in
        var bytes = Array(line)
        if bytes.last == 0x0D {
            bytes.removeLast()
        }
        return String(decoding: bytes, as: UTF8.self)
    })
}
