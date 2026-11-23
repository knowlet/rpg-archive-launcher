//! Single-threaded read-only libfuse2 adapter. Writable POSIX mounts deliberately
//! remain unsupported; the independent Upper API is tested separately.
use crate::{filesystem::Filesystem, worker::DecoderWorker};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString, c_char, c_int, c_void},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};
#[repr(C)]
struct Metadata {
    size: u64,
    directory: u32,
    permissions: u32,
}
type Emit = unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int;
#[repr(C)]
struct Callbacks {
    getattr: unsafe extern "C" fn(*mut c_void, *const c_char, *mut Metadata) -> c_int,
    readdir: unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void, Emit) -> c_int,
    access: unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int,
    open:
        unsafe extern "C" fn(*mut c_void, *const c_char, c_int, c_int, *mut u64, *mut u32) -> c_int,
    read: unsafe extern "C" fn(*mut c_void, u64, *mut c_char, usize, i64) -> c_int,
    write: unsafe extern "C" fn(*mut c_void, u64, *const c_char, usize, i64) -> c_int,
    truncate: unsafe extern "C" fn(*mut c_void, *const c_char, u64, i64) -> c_int,
    unlink: unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int,
    rename: unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> c_int,
    fsync: unsafe extern "C" fn(*mut c_void, u64) -> c_int,
    release: unsafe extern "C" fn(*mut c_void, u64) -> c_int,
}
unsafe extern "C" {
    fn rpg_fuse_main(
        argc: c_int,
        argv: *mut *mut c_char,
        state: *mut c_void,
        callbacks: *const Callbacks,
    ) -> c_int;
}
struct State {
    fs: Filesystem<DecoderWorker>,
    handles: BTreeMap<u64, String>,
    next: u64,
}
fn errno(error: String) -> c_int {
    match error.as_str() {
        "file not found" => -libc::ENOENT,
        "is a directory" => -libc::EISDIR,
        "not a directory" => -libc::ENOTDIR,
        _ => -libc::EIO,
    }
}
fn boundary(f: impl FnOnce() -> Result<c_int, c_int>) -> c_int {
    catch_unwind(AssertUnwindSafe(f))
        .unwrap_or(Err(-libc::EIO))
        .unwrap_or_else(|e| e)
}
unsafe fn state<'a>(p: *mut c_void) -> Result<&'a mut State, c_int> {
    if p.is_null() {
        Err(-libc::EIO)
    } else {
        Ok(unsafe { &mut *p.cast::<State>() })
    }
}
unsafe fn path<'a>(p: *const c_char) -> Result<&'a str, c_int> {
    if p.is_null() {
        return Err(-libc::EINVAL);
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| -libc::EINVAL)
}
unsafe extern "C" fn getattr(s: *mut c_void, p: *const c_char, out: *mut Metadata) -> c_int {
    boundary(|| {
        if out.is_null() {
            return Err(-libc::EINVAL);
        }
        let m = unsafe { state(s)? }
            .fs
            .metadata(unsafe { path(p)? })
            .map_err(errno)?;
        unsafe {
            *out = Metadata {
                size: m.size,
                directory: u32::from(m.directory),
                permissions: if m.directory { 0o500 } else { 0o400 },
            }
        };
        Ok(0)
    })
}
unsafe extern "C" fn readdir(
    s: *mut c_void,
    p: *const c_char,
    out: *mut c_void,
    emit: Emit,
) -> c_int {
    boundary(|| {
        let names = unsafe { state(s)? }
            .fs
            .readdir(unsafe { path(p)? })
            .map_err(errno)?;
        for name in [".".to_string(), "..".to_string()].into_iter().chain(names) {
            let name = CString::new(name).map_err(|_| -libc::EINVAL)?;
            if unsafe { emit(out, name.as_ptr()) } != 0 {
                break;
            }
        }
        Ok(0)
    })
}
unsafe extern "C" fn access(s: *mut c_void, p: *const c_char, mask: c_int) -> c_int {
    boundary(|| {
        let m = unsafe { state(s)? }
            .fs
            .metadata(unsafe { path(p)? })
            .map_err(errno)?;
        if mask & libc::W_OK != 0 {
            return Err(-libc::EROFS);
        }
        if mask & libc::X_OK != 0 && !m.directory {
            return Err(-libc::EACCES);
        }
        Ok(0)
    })
}
unsafe extern "C" fn open(
    s: *mut c_void,
    p: *const c_char,
    flags: c_int,
    create: c_int,
    handle: *mut u64,
    direct: *mut u32,
) -> c_int {
    boundary(|| {
        if create != 0
            || flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags & (libc::O_TRUNC | libc::O_APPEND | libc::O_CREAT) != 0
        {
            return Err(-libc::EROFS);
        }
        if handle.is_null() || direct.is_null() {
            return Err(-libc::EINVAL);
        }
        let s = unsafe { state(s)? };
        let p = unsafe { path(p)? };
        if s.fs.metadata(p).map_err(errno)?.directory {
            return Err(-libc::EISDIR);
        }
        if s.handles.len() >= 1024 {
            return Err(-libc::EMFILE);
        }
        s.next = s.next.checked_add(1).ok_or(-libc::EOVERFLOW)?;
        s.handles.insert(s.next, p.into());
        unsafe {
            *handle = s.next;
            *direct = 1;
        }
        Ok(0)
    })
}
unsafe extern "C" fn read(
    s: *mut c_void,
    h: u64,
    out: *mut c_char,
    length: usize,
    offset: i64,
) -> c_int {
    boundary(|| {
        if offset < 0 || length > 16 * 1024 * 1024 || out.is_null() {
            return Err(-libc::EINVAL);
        }
        let s = unsafe { state(s)? };
        let path = s.handles.get(&h).ok_or(-libc::EBADF)?.clone();
        let data = s.fs.read_at(&path, offset as u64, length).map_err(errno)?;
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), out.cast(), data.len());
        }
        Ok(data.len() as c_int)
    })
}
unsafe extern "C" fn write(_: *mut c_void, _: u64, _: *const c_char, _: usize, _: i64) -> c_int {
    -libc::EROFS
}
unsafe extern "C" fn truncate(_: *mut c_void, _: *const c_char, _: u64, _: i64) -> c_int {
    -libc::EROFS
}
unsafe extern "C" fn unlink(_: *mut c_void, _: *const c_char) -> c_int {
    -libc::EROFS
}
unsafe extern "C" fn rename(_: *mut c_void, _: *const c_char, _: *const c_char) -> c_int {
    -libc::EROFS
}
unsafe extern "C" fn fsync(s: *mut c_void, h: u64) -> c_int {
    boundary(|| {
        if unsafe { state(s)? }.handles.contains_key(&h) {
            Ok(0)
        } else {
            Err(-libc::EBADF)
        }
    })
}
unsafe extern "C" fn release(s: *mut c_void, h: u64) -> c_int {
    boundary(|| {
        unsafe { state(s)? }
            .handles
            .remove(&h)
            .ok_or(-libc::EBADF)?;
        Ok(0)
    })
}

pub fn readonly(
    fs: Filesystem<DecoderWorker>,
    mountpoint: &Path,
    fskit: bool,
) -> Result<(), String> {
    if fskit && !cfg!(target_os = "macos") {
        return Err("FSKit is available only on macOS".into());
    }
    #[cfg(target_os = "macos")]
    {
        let version = std::process::Command::new("/usr/bin/sw_vers")
            .arg("-productVersion")
            .output()
            .map_err(|e| e.to_string())?;
        if !version.status.success()
            || !crate::platform::macos_version_supported(
                &String::from_utf8_lossy(&version.stdout),
                fskit,
            )
        {
            return Err("macOS version is ineligible for selected backend".into());
        }
        crate::platform::require_macfuse_55().map_err(|e| e.to_string())?;
    }
    let mountpoint =
        crate::platform::validate_mountpoint(mountpoint, fskit).map_err(|e| e.to_string())?;
    let mountpoint = mountpoint.to_str().ok_or("mountpoint must be UTF-8")?;
    let mut args = vec![
        "rpg-archive-launcher",
        "-f",
        "-s",
        "-o",
        "ro,nodev,nosuid,noexec,attr_timeout=0,entry_timeout=0",
        mountpoint,
    ];
    if fskit {
        args.extend(["-o", "backend=fskit"]);
    }
    let strings = args
        .iter()
        .map(|v| CString::new(*v).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut pointers = strings
        .iter()
        .map(|s| s.as_ptr() as *mut c_char)
        .collect::<Vec<_>>();
    let mut state = State {
        fs,
        handles: BTreeMap::new(),
        next: 0,
    };
    let callbacks = Callbacks {
        getattr,
        readdir,
        access,
        open,
        read,
        write,
        truncate,
        unlink,
        rename,
        fsync,
        release,
    };
    // SAFETY: libfuse owns no Rust data, and -s forces serialized callbacks.
    // The state, strings, and callback table outlive fuse_main. Each callback
    // catches Rust unwinds and validates primitive arguments before use.
    let result = unsafe {
        rpg_fuse_main(
            pointers.len() as c_int,
            pointers.as_mut_ptr(),
            (&mut state as *mut State).cast(),
            &callbacks,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!("mount exited with status {result}"))
    }
}
