//! Explicit process-wide resource policy for Linux archive hosts.
//!
//! Install before loading untrusted input in a dedicated process, never silently
//! in an embedding GUI/server. Hard limits cannot normally be raised afterward.
//! CPU time is cumulative for the process, not a per-request timeout. Address
//! space is not RSS; limits do not undo existing allocations. Exhaustion can
//! abort/kill the host, so callers needing recovery must supervise a child.
//! This is not a filesystem/network sandbox or protection from a privileged host
//! that deliberately changes limits. Other platforms are not validated.
use std::io;

pub const MAX_ADDRESS_SPACE_BYTES: u64 = 512 << 20;
pub const MAX_CPU_SECONDS: u64 = 120;

#[cfg(target_os = "linux")]
fn current(resource: libc::c_int) -> io::Result<libc::rlimit> {
    let mut value = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: value is a valid writable rlimit and resource is an OS constant.
    if unsafe { libc::getrlimit(resource as _, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

/// Check before opening an archive or constructing its password/decoder.
/// Both hard ceilings must be finite and no greater than the documented policy.
#[cfg(target_os = "linux")]
pub fn require_process_limits() -> io::Result<()> {
    for (resource, maximum) in [
        (libc::RLIMIT_AS, MAX_ADDRESS_SPACE_BYTES),
        (libc::RLIMIT_CPU, MAX_CPU_SECONDS),
    ] {
        let maximum = maximum as libc::rlim_t;
        let value = current(resource as _)?;
        if value.rlim_max == libc::RLIM_INFINITY || value.rlim_max > maximum {
            return Err(io::Error::other(
                "archive requires Linux hard process limits: address space <=512 MiB and cumulative CPU <=120 seconds; explicitly configure a dedicated archive host first",
            ));
        }
    }
    Ok(())
}

/// Opt in to irreversible process-wide ceilings, preserving stricter limits.
/// On failure, a preceding limit may already have been lowered; do not parse.
#[cfg(target_os = "linux")]
pub fn install_process_limits() -> io::Result<()> {
    for (resource, maximum) in [
        (libc::RLIMIT_AS, MAX_ADDRESS_SPACE_BYTES),
        (libc::RLIMIT_CPU, MAX_CPU_SECONDS),
    ] {
        let maximum = maximum as libc::rlim_t;
        let old = current(resource as _)?;
        let value = libc::rlimit {
            rlim_cur: old.rlim_cur.min(maximum),
            rlim_max: old.rlim_max.min(maximum),
        };
        // SAFETY: value is a valid rlimit; this explicitly lowers process limits.
        if unsafe { libc::setrlimit(resource as _, &value) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    require_process_limits()
}

#[cfg(not(target_os = "linux"))]
pub fn require_process_limits() -> io::Result<()> {
    Err(io::Error::other(
        "archive access requires validated Linux process limits; other platforms are unsupported in this prototype",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn install_process_limits() -> io::Result<()> {
    require_process_limits()
}
