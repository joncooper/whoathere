#[cfg(target_os = "linux")]
fn main() {
    use std::ffi::OsStr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let mut arguments = std::env::args_os();
    let program = arguments.next();
    let fixture_case = arguments.next();
    if program.is_none() || arguments.next().is_some() {
        std::process::exit(75);
    }
    let (continuous_drain, exercise_file_sensor, exercise_network_sensor) =
        match fixture_case.as_deref() {
            Some(value) if value == OsStr::new("normal_exit") => (false, false, false),
            Some(value) if value == OsStr::new("continuous_drain") => (true, true, true),
            Some(value) if value == OsStr::new("fault_signal") => (true, false, false),
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
        if exercise_network_sensor {
            let tcp =
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            if tcp < 0 {
                std::process::exit(82);
            }
            let tcp = unsafe { OwnedFd::from_raw_fd(tcp) };
            let ipv4_target = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 443_u16.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes([192, 0, 2, 9]),
                },
                sin_zero: [0; 8],
            };
            let connect_result = unsafe {
                libc::connect(
                    tcp.as_raw_fd(),
                    (&ipv4_target as *const libc::sockaddr_in).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            let connect_errno = (connect_result == -1)
                .then(|| std::io::Error::last_os_error().raw_os_error())
                .flatten();
            if connect_result != -1 || connect_errno != Some(libc::ENETUNREACH) {
                eprintln!(
                    "WHOATHERE_PACKAGE_SENSOR_BPF_INERT_NETWORK_FAILURE operation=connect result={connect_result} errno={}",
                    connect_errno.unwrap_or(0)
                );
                std::process::exit(83);
            }

            let udp =
                unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            if udp < 0 {
                std::process::exit(84);
            }
            let udp = unsafe { OwnedFd::from_raw_fd(udp) };
            let ipv6_target = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 53_u16.to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
                },
                sin6_scope_id: 0,
            };
            let marker = [0x57_u8];
            let send_result = unsafe {
                libc::sendto(
                    udp.as_raw_fd(),
                    marker.as_ptr().cast(),
                    marker.len(),
                    0,
                    (&ipv6_target as *const libc::sockaddr_in6).cast(),
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            };
            let send_errno = (send_result == -1)
                .then(|| std::io::Error::last_os_error().raw_os_error())
                .flatten();
            if send_result != -1 || send_errno != Some(libc::EADDRNOTAVAIL) {
                eprintln!(
                    "WHOATHERE_PACKAGE_SENSOR_BPF_INERT_NETWORK_FAILURE operation=sendto result={send_result} errno={}",
                    send_errno.unwrap_or(0)
                );
                std::process::exit(85);
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
