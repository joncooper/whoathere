#[cfg(target_os = "linux")]
fn main() {
    use std::ffi::OsStr;

    let mut arguments = std::env::args_os();
    let program = arguments.next();
    let fixture_case = arguments.next();
    if program.is_none()
        || fixture_case.as_deref() != Some(OsStr::new("normal_exit"))
        || arguments.next().is_some()
    {
        std::process::exit(75);
    }
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
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("whoathere package-sensor BPF inert fixture is Linux-only");
    std::process::exit(64);
}
