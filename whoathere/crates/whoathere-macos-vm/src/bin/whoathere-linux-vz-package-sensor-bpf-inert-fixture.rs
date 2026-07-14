#[cfg(target_os = "linux")]
fn main() {
    use std::ffi::OsStr;

    let mut arguments = std::env::args_os();
    let program = arguments.next();
    let fixture_case = arguments.next();
    if program.is_none() || arguments.next().is_some() {
        std::process::exit(75);
    }
    let (continuous_drain, exercise_file_sensor) = match fixture_case.as_deref() {
        Some(value) if value == OsStr::new("normal_exit") => (false, false),
        Some(value) if value == OsStr::new("continuous_drain") => (true, true),
        Some(value) if value == OsStr::new("fault_signal") => (true, false),
        _ => std::process::exit(75),
    };
    if unsafe { libc::getuid() } != 65_534
        || unsafe { libc::geteuid() } != 65_534
        || unsafe { libc::getgid() } != 65_534
        || unsafe { libc::getegid() } != 65_534
    {
        std::process::exit(76);
    }
    if unsafe { libc::getgroups(0, std::ptr::null_mut()) } != 0 {
        std::process::exit(77);
    }
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
        std::process::exit(78);
    }
    let mut core_limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core_limit) } != 0
        || core_limit.rlim_cur != 0
        || core_limit.rlim_max != 0
    {
        std::process::exit(79);
    }
    if continuous_drain {
        if exercise_file_sensor {
            let before = "/run/whoathere/work/file-sensor-fixture-before";
            let after = "/run/whoathere/work/file-sensor-fixture-after";
            match std::fs::read(before) {
                Ok(bytes) if bytes == b"before\n" => {}
                Ok(_) => {
                    eprintln!("WHOATHERE_FILE_FIXTURE_DETAIL stage=read_before_content errno=0");
                    std::process::exit(80);
                }
                Err(error) => {
                    eprintln!(
                        "WHOATHERE_FILE_FIXTURE_DETAIL stage=read_before errno={}",
                        error.raw_os_error().unwrap_or(0)
                    );
                    std::process::exit(80);
                }
            }
            if let Err(error) = std::fs::write(before, b"after\n") {
                eprintln!(
                    "WHOATHERE_FILE_FIXTURE_DETAIL stage=write errno={}",
                    error.raw_os_error().unwrap_or(0)
                );
                std::process::exit(80);
            }
            if let Err(error) = std::fs::rename(before, after) {
                eprintln!(
                    "WHOATHERE_FILE_FIXTURE_DETAIL stage=rename errno={}",
                    error.raw_os_error().unwrap_or(0)
                );
                std::process::exit(80);
            }
            if !matches!(std::fs::read(after), Ok(bytes) if bytes == b"after\n") {
                eprintln!("WHOATHERE_FILE_FIXTURE_DETAIL stage=read_after errno=0");
                std::process::exit(80);
            }
        }
        let duration = libc::timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        };
        if unsafe { libc::nanosleep(&duration, std::ptr::null_mut()) } != 0 {
            std::process::exit(81);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("whoathere package-sensor BPF inert fixture is Linux-only");
    std::process::exit(64);
}
