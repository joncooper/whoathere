use whoathere_macos_vm::run_linux_vz_package_sensor_bpf_inert_probe_v1;

fn main() {
    match run_linux_vz_package_sensor_bpf_inert_probe_v1() {
        Ok(evidence) => {
            println!("WHOATHERE_PACKAGE_SENSOR_BPF_INERT_EVIDENCE {evidence}");
        }
        Err(error) => {
            eprintln!("WHOATHERE_PACKAGE_SENSOR_BPF_INERT_FAILED {error}");
            std::process::exit(70);
        }
    }
}
