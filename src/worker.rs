//! Bounded, supervised decoder process. This is resource isolation, not an OS
//! filesystem/network sandbox. macOS RSS enforcement is sampled, not a hard cap.
use crate::archive::ArchiveSource;
use std::{
    io::{self, Read, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

pub const MAX_RESPONSE: usize = 16 * 1024 * 1024 + 1;
const MAX_REQUEST: usize = 16 * 1024;
const MAX_METADATA: usize = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 16384;
const TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(20);
/// After the child exits, how long its final reply may take to arrive. Only a
/// descendant still holding stdout keeps the pipe open past the exit.
const EXIT_GRACE: Duration = Duration::from_secs(1);
/// How long Drop waits for the reader thread before detaching it.
const READER_JOIN: Duration = Duration::from_secs(2);
type Result<T> = std::result::Result<T, String>;

pub(crate) struct WorkerPermit {
    _private: (),
}
impl WorkerPermit {
    pub(crate) fn verify(&self) -> Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            crate::isolation::require_worker_limits().map_err(|e| e.to_string())
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err("decoder worker unsupported on this OS".into())
        }
    }
}
fn frame_read(input: &mut impl Read, maximum: usize) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    input.read_exact(&mut header)?;
    let length = u32::from_le_bytes(header) as usize;
    if length > maximum {
        return Err(io::Error::other("worker frame exceeds limit"));
    }
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn frame_write(output: &mut impl Write, data: &[u8], maximum: usize) -> io::Result<()> {
    if data.len() > maximum {
        return Err(io::Error::other("worker frame exceeds limit"));
    }
    output.write_all(&(data.len() as u32).to_le_bytes())?;
    output.write_all(data)?;
    output.flush()
}
fn response(output: &mut impl Write, result: Result<Vec<u8>>) -> io::Result<()> {
    // A single oversized payload must become a normal error frame. Failing the
    // write here ends the child and makes every later read on the mount EIO.
    let (status, data) = match result {
        Ok(data) if data.len() < MAX_RESPONSE => (0, data),
        Ok(_) => (1, b"worker response exceeds limit".to_vec()),
        Err(error) => {
            let bytes = error.into_bytes();
            if bytes.len() < MAX_RESPONSE {
                (1, bytes)
            } else {
                (1, b"worker error exceeds limit".to_vec())
            }
        }
    };
    let mut framed = Vec::with_capacity(data.len() + 1);
    framed.push(status);
    framed.extend_from_slice(&data);
    frame_write(output, &framed, MAX_RESPONSE)
}

/// Internal child entry point. Call only from the executable's decoder command.
/// Limits are installed before reading the archive path, password, or metadata.
pub fn serve() -> Result<()> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err("decoder worker unsupported on this OS".into());
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        crate::isolation::install_worker_limits().map_err(|e| e.to_string())?;
        let permit = WorkerPermit { _private: () };
        let mut input = io::stdin().lock();
        let mut output = io::stdout().lock();
        let init = frame_read(&mut input, MAX_REQUEST).map_err(|e| e.to_string())?;
        let (path, password): (String, String) =
            serde_json::from_slice(&init).map_err(|e| e.to_string())?;
        if password.len() > 4096 {
            return Err("password exceeds limit".into());
        }
        let opened = crate::archive::Archive::open_worker(
            path,
            &password,
            crate::archive::Limits {
                max_file_bytes: (MAX_RESPONSE - 1) as u64,
                max_cache_bytes: (MAX_RESPONSE - 1) as u64,
                max_entries: MAX_ENTRIES,
                ..crate::archive::Limits::default()
            },
            &permit,
        );
        drop(password);
        drop(init);
        let mut archive = match opened {
            Ok(a) => a,
            Err(e) => {
                response(&mut output, Err(e)).map_err(|e| e.to_string())?;
                return Ok(());
            }
        };
        let metadata = (|| {
            let entries = archive.bounded_entries(MAX_ENTRIES, MAX_METADATA)?;
            let revision = archive.revision_sha256()?;
            let bytes = serde_json::to_vec(&(entries, revision)).map_err(|e| e.to_string())?;
            if bytes.len() > MAX_METADATA {
                return Err("serialized metadata exceeds limit".into());
            }
            Ok(bytes)
        })();
        let valid = metadata.is_ok();
        response(&mut output, metadata).map_err(|e| e.to_string())?;
        if !valid {
            return Ok(());
        }
        loop {
            let request = match frame_read(&mut input, MAX_REQUEST) {
                Ok(v) => v,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e.to_string()),
            };
            // null: revalidate the source; "path": whole entry;
            // ["path", offset, length]: a slice cut here, not in the parent.
            let request: serde_json::Value =
                serde_json::from_slice(&request).map_err(|e| e.to_string())?;
            let result = match request {
                serde_json::Value::Null => archive.ensure_source_unchanged().map(|()| Vec::new()),
                serde_json::Value::String(p) => archive.read(&p),
                serde_json::Value::Array(items) => match items.as_slice() {
                    [
                        serde_json::Value::String(p),
                        serde_json::Value::Number(offset),
                        serde_json::Value::Number(length),
                    ] => match (offset.as_u64(), length.as_u64()) {
                        (Some(offset), Some(length)) if length < MAX_RESPONSE as u64 => {
                            archive.read_range(p, offset, length as usize)
                        }
                        _ => Err("invalid range request".into()),
                    },
                    _ => return Err("malformed worker request".into()),
                },
                _ => return Err("malformed worker request".into()),
            };
            response(&mut output, result).map_err(|e| e.to_string())?;
        }
    }
}

pub struct DecoderWorker {
    child: Child,
    input: Option<ChildStdin>,
    replies: Receiver<io::Result<Vec<u8>>>,
    reader: Option<thread::JoinHandle<()>>,
    entries: Vec<(String, Option<u64>)>,
    revision: [u8; 32],
    failed: bool,
    reaped: bool,
    watchdog: Option<thread::JoinHandle<()>>,
    watch_stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    watch_failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
#[cfg(unix)]
enum GroupSweep {
    /// `waitpid` returned `ECHILD`: this process has no child in the group.
    Empty { saw_leader: bool },
    /// `waitpid` returned 0: a child in the group has not exited.
    Live { saw_leader: bool },
}

#[cfg(unix)]
enum GroupWait {
    Reaped(i32),
    /// `WNOHANG` and a child in the group has not exited. `errno` is unchanged.
    Alive,
    /// No child of this process is in the group.
    Empty,
    /// `waitpid` failed with something other than `EINTR` or `ECHILD`.
    Failed,
}

/// One nonblocking drain of `pid`'s process group.
///
/// `0` (still alive) and `ECHILD` (empty) are different results. `EINTR` is
/// retried inside [`wait_group`]. Any other error stays unfinished so the
/// caller does not report the group collected.
#[cfg(unix)]
fn sweep_group(pid: i32) -> GroupSweep {
    let mut saw_leader = false;
    loop {
        match wait_group(pid, libc::WNOHANG) {
            GroupWait::Reaped(waited) if waited == pid => saw_leader = true,
            GroupWait::Reaped(_) => {}
            GroupWait::Empty => return GroupSweep::Empty { saw_leader },
            GroupWait::Alive | GroupWait::Failed => return GroupSweep::Live { saw_leader },
        }
    }
}

/// `waitpid(-pid, flags)`, retrying `EINTR`.
///
/// A return of 0 is [`GroupWait::Alive`] and is not confused with `ECHILD`.
#[cfg(unix)]
fn wait_group(pid: i32, flags: libc::c_int) -> GroupWait {
    loop {
        let waited = unsafe { libc::waitpid(-pid, std::ptr::null_mut(), flags) };
        if waited > 0 {
            return GroupWait::Reaped(waited);
        }
        if waited == 0 {
            return GroupWait::Alive;
        }
        match io::Error::last_os_error().raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::ECHILD) => return GroupWait::Empty,
            _ => return GroupWait::Failed,
        }
    }
}

impl DecoderWorker {
    pub fn spawn(executable: &Path, archive: &Path, password: &str) -> Result<Self> {
        if !cfg!(any(target_os = "linux", target_os = "macos")) {
            return Err("decoder worker unsupported on this OS".into());
        }
        if password.len() > 4096 {
            return Err("password exceeds limit".into());
        }
        let path = archive.to_str().ok_or("archive path must be UTF-8")?;
        let init = serde_json::to_vec(&(path, password)).map_err(|e| e.to_string())?;
        if init.len() > MAX_REQUEST {
            return Err("worker initialization exceeds limit".into());
        }
        let mut command = Command::new(executable);
        command
            .arg("__decoder-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // Its own process group, so stop() also kills any descendant that
        // inherited the pipes; otherwise one could keep stdout open forever.
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        let mut child = command.spawn().map_err(|e| e.to_string())?;
        let input = child.stdin.take();
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let fd = input.as_ref().ok_or("worker stdin missing")?.as_raw_fd();
            // A stalled child must not block the supervisor in a pipe write.
            if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                let _ = child.kill();
                let _ = child.wait();
                return Err("cannot make worker pipe nonblocking".into());
            }
        }
        let watch_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watch_failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = watch_stop.clone();
        let failed = watch_failed.clone();
        let pid = child.id();
        let watchdog = thread::spawn(move || {
            use std::sync::atomic::Ordering::SeqCst;
            while !stop.load(SeqCst) {
                if rss_bytes(pid)
                    .map_or(true, |rss| rss > crate::isolation::MAX_ADDRESS_SPACE_BYTES)
                {
                    failed.store(true, SeqCst);
                    // The owner does not reap until this watcher has joined,
                    // so this PID cannot be reused while it can be signalled.
                    #[cfg(unix)]
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                    break;
                }
                thread::sleep(POLL);
            }
        });
        let mut stdout = child.stdout.take().ok_or("worker stdout missing")?;
        let (send, replies) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            loop {
                let reply = frame_read(&mut stdout, MAX_RESPONSE);
                let failed = reply.is_err();
                if send.send(reply).is_err() || failed {
                    break;
                }
            }
        });
        let mut worker = Self {
            child,
            input,
            replies,
            reader: Some(reader),
            entries: Vec::new(),
            revision: [0; 32],
            failed: false,
            reaped: false,
            watchdog: Some(watchdog),
            watch_stop,
            watch_failed,
        };
        let bytes = worker.exchange(&init)?;
        if bytes.len() > MAX_METADATA {
            return Err("worker metadata exceeds limit".into());
        }
        let (entries, revision): (Vec<(String, Option<u64>)>, [u8; 32]) =
            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if entries.len() > MAX_ENTRIES {
            return Err("worker entry count exceeds limit".into());
        }
        for (path, _) in &entries {
            crate::archive::validate_archive_path(path)?;
        }
        worker.entries = entries;
        worker.revision = revision;
        Ok(worker)
    }
    fn stop(&mut self) {
        self.failed = true;
        self.input.take();
        self.watch_stop
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(watchdog) = self.watchdog.take() {
            let _ = watchdog.join();
        }
        if !self.reaped {
            // The group leader is not reaped yet, so its PID (the group ID)
            // cannot have been reused. `reaped` is set only after waitpid
            // collects that pid, or after a background reaper owns the wait.
            #[cfg(unix)]
            {
                let pid = self.child.id() as i32;
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
                if !Self::collect_group(pid, Duration::from_millis(200)) {
                    // The leader has not been collected, or a descendant is
                    // still alive (waitpid returned 0, not ECHILD). The reaper
                    // blocks until the group is empty.
                    Self::reap_in_background(pid);
                }
                self.reaped = true;
            }
            #[cfg(not(unix))]
            {
                let _ = self.child.kill();
                self.reaped = self.child.wait().is_ok();
            }
        }
    }
    /// Nonblocking collection of `pid`'s process group.
    ///
    /// True only when the leader has been collected and `waitpid` reports
    /// `ECHILD` (no member remains). A return of 0 means a descendant is still
    /// alive, which is not success: `stop` then hands the group to the
    /// background reaper. `EINTR` is retried.
    #[cfg(unix)]
    fn collect_group(pid: i32, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        let mut leader = false;
        loop {
            match sweep_group(pid) {
                GroupSweep::Empty { saw_leader } => {
                    leader |= saw_leader;
                    return leader;
                }
                GroupSweep::Live { saw_leader } => {
                    leader |= saw_leader;
                    if Instant::now() >= deadline {
                        return false;
                    }
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Block until every child in `pid`'s process group has been collected.
    ///
    /// `waitpid` of 0 cannot occur without `WNOHANG`. `EINTR` is retried.
    /// `ECHILD` means the group is empty, including a descendant that was
    /// still running when the leader was collected.
    #[cfg(unix)]
    fn reap_in_background(pid: i32) {
        thread::spawn(
            move || {
                while matches!(wait_group(pid, 0), GroupWait::Reaped(_)) {}
            },
        );
    }

    /// Whether the child has exited, without reaping it (the watchdog may
    /// still signal its PID).
    fn child_exited(&self) -> bool {
        #[cfg(unix)]
        {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let status = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            status == 0 && unsafe { info.si_pid() } != 0
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
    /// Logical read failures stay on that call. Transport, timeout, supervision,
    /// and malformed frames retire the child; an oversized entry must not.
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        if self.failed {
            return Err("decoder worker is unavailable".into());
        }
        match self.exchange_inner(request) {
            Ok(data) => Ok(data),
            Err(error) if error.fatal => {
                self.stop();
                Err(error.message)
            }
            Err(error) => Err(error.message),
        }
    }
    fn check_watchdog(&self, start: Instant) -> std::result::Result<(), ExchangeError> {
        if start.elapsed() >= TIMEOUT {
            return Err(ExchangeError::fatal("decoder worker wall timeout"));
        }
        if self.watch_failed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ExchangeError::fatal(
                "decoder worker RSS supervision failed or exceeded limit",
            ));
        }
        Ok(())
    }
    fn exchange_inner(&mut self, request: &[u8]) -> std::result::Result<Vec<u8>, ExchangeError> {
        if request.len() > MAX_REQUEST {
            return Err(ExchangeError::rejected("worker request exceeds limit"));
        }
        let start = Instant::now();
        let mut frame = Vec::with_capacity(request.len() + 4);
        frame.extend_from_slice(&(request.len() as u32).to_le_bytes());
        frame.extend_from_slice(request);
        let mut sent = 0;
        while sent < frame.len() {
            self.check_watchdog(start)?;
            match self
                .input
                .as_mut()
                .ok_or_else(|| ExchangeError::fatal("worker closed"))?
                .write(&frame[sent..])
            {
                Ok(0) => return Err(ExchangeError::fatal("worker pipe closed")),
                Ok(n) => sent += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(ExchangeError::fatal(e.to_string())),
            }
        }
        let mut exited_at: Option<Instant> = None;
        loop {
            self.check_watchdog(start)?;
            match self.replies.recv_timeout(POLL) {
                Ok(reply) => {
                    let mut data = reply.map_err(|e| ExchangeError::fatal(e.to_string()))?;
                    if data.is_empty() {
                        return Err(ExchangeError::fatal("empty worker response"));
                    }
                    let status = data.remove(0);
                    return match status {
                        0 => Ok(data),
                        1 => Err(ExchangeError::rejected(
                            String::from_utf8_lossy(&data).into_owned(),
                        )),
                        _ => Err(ExchangeError::fatal("invalid worker response status")),
                    };
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(at) = exited_at {
                        if at.elapsed() >= EXIT_GRACE {
                            return Err(ExchangeError::fatal("decoder worker exited"));
                        }
                    } else if self.child_exited() {
                        exited_at = Some(Instant::now());
                    }
                }
                Err(_) => return Err(ExchangeError::fatal("decoder worker EOF")),
            }
        }
    }
}

struct ExchangeError {
    fatal: bool,
    message: String,
}
impl ExchangeError {
    fn fatal(message: impl Into<String>) -> Self {
        Self {
            fatal: true,
            message: message.into(),
        }
    }
    fn rejected(message: impl Into<String>) -> Self {
        Self {
            fatal: false,
            message: message.into(),
        }
    }
}
impl ArchiveSource for DecoderWorker {
    fn entries(&self) -> Vec<(String, Option<u64>)> {
        self.entries.clone()
    }
    fn read(&mut self, path: &str) -> Result<Vec<u8>> {
        crate::archive::validate_archive_path(path)?;
        self.exchange(&serde_json::to_vec(&Some(path)).map_err(|e| e.to_string())?)
    }
    fn read_range(&mut self, path: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
        crate::archive::validate_archive_path(path)?;
        let data = self
            .exchange(&serde_json::to_vec(&(path, offset, length)).map_err(|e| e.to_string())?)?;
        if data.len() > length {
            // A reply larger than the request is a broken worker, not a
            // logical read error. Do not use it again.
            self.stop();
            return Err("worker returned more than the requested range".into());
        }
        Ok(data)
    }
    fn revision_sha256(&mut self) -> Result<[u8; 32]> {
        self.exchange(b"null")?;
        Ok(self.revision)
    }
}
impl Drop for DecoderWorker {
    fn drop(&mut self) {
        self.stop();
        // Closing the receiver before joining unblocks a producer that filled
        // the single bounded response slot.
        let (_, empty) = mpsc::channel();
        let old = std::mem::replace(&mut self.replies, empty);
        drop(old);
        if let Some(reader) = self.reader.take() {
            // The group kill normally closes stdout at once. A descendant that
            // left the group could still hold it; then detach rather than let
            // Drop (and an unmount) hang on the blocked read.
            let deadline = Instant::now() + READER_JOIN;
            while !reader.is_finished() && Instant::now() < deadline {
                thread::sleep(POLL);
            }
            if reader.is_finished() {
                let _ = reader.join();
            }
        }
    }
}
#[cfg(target_os = "linux")]
fn rss_bytes(pid: u32) -> Result<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/statm")).map_err(|e| e.to_string())?;
    let pages = text
        .split_whitespace()
        .nth(1)
        .ok_or("missing worker RSS")?
        .parse::<u64>()
        .map_err(|e| e.to_string())?;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 {
        return Err("unable to determine page size".into());
    }
    pages
        .checked_mul(page as u64)
        .ok_or("worker RSS overflow".into())
}
#[cfg(target_os = "macos")]
fn rss_bytes(pid: u32) -> Result<u64> {
    // libproc's task-info API reads the child directly without spawning ps.
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let expected = std::mem::size_of_val(&info) as i32;
    let read = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTASKINFO,
            0,
            (&mut info as *mut libc::proc_taskinfo).cast(),
            expected,
        )
    };
    if read != expected {
        return Err("unable to sample decoder RSS; refusing unsupervised decoding".into());
    }
    Ok(info.pti_resident_size)
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rss_bytes(_: u32) -> Result<u64> {
    Err("RSS supervision unavailable".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_limits_before_allocation() {
        assert!(frame_read(&mut &u32::MAX.to_le_bytes()[..], 4).is_err());
        assert!(frame_write(&mut Vec::new(), b"12345", 4).is_err());
    }
    #[test]
    fn truncated_frame_fails() {
        assert!(frame_read(&mut &[3, 0, 0, 0, 1][..], 4).is_err());
    }
    #[test]
    fn oversized_payload_is_an_error_frame_and_the_stream_continues() {
        let mut output = Vec::new();
        response(&mut output, Ok(vec![9; MAX_RESPONSE])).unwrap();
        response(&mut output, Ok(b"next".to_vec())).unwrap();
        let mut cursor = std::io::Cursor::new(output);
        let first = frame_read(&mut cursor, MAX_RESPONSE).unwrap();
        assert_eq!(first[0], 1);
        assert!(
            std::str::from_utf8(&first[1..])
                .unwrap()
                .contains("exceeds limit")
        );
        assert_eq!(frame_read(&mut cursor, MAX_RESPONSE).unwrap(), b"\0next");
    }

    #[cfg(unix)]
    #[test]
    fn uncollected_leader_is_reaped_after_it_exits() {
        use std::os::unix::process::CommandExt;
        let child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        assert!(
            !DecoderWorker::collect_group(pid, std::time::Duration::ZERO),
            "a live child must not count as collected"
        );
        assert_eq!(unsafe { libc::kill(pid, 0) }, 0);
        DecoderWorker::reap_in_background(pid);
        assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
        // Dropping Child would not wait. Forget it so only the reaper collects.
        std::mem::forget(child);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if unsafe { libc::kill(pid, 0) } != 0 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("pid {pid} was still visible after the background reaper");
    }

    /// The leader is already a zombie and a second child in its group is still
    /// running. `collect_group` must not report success: `waitpid` returns 0,
    /// not `ECHILD`, and `stop` has to keep a reaper.
    #[cfg(unix)]
    #[test]
    fn live_descendant_keeps_the_group_unfinished() {
        use std::os::unix::process::CommandExt;
        let leader = std::process::Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let pgid = leader.id() as i32;
        let descendant = std::process::Command::new("/bin/sleep")
            .arg("30")
            .process_group(pgid)
            .spawn()
            .unwrap();
        let dpid = descendant.id() as i32;
        assert_eq!(unsafe { libc::kill(pgid, libc::SIGKILL) }, 0);
        assert!(
            !DecoderWorker::collect_group(pgid, std::time::Duration::from_millis(50)),
            "a live descendant must not count as a finished group"
        );
        assert_eq!(
            unsafe { libc::kill(dpid, 0) },
            0,
            "descendant must still be alive when collection stops"
        );
        DecoderWorker::reap_in_background(pgid);
        assert_eq!(unsafe { libc::kill(dpid, libc::SIGKILL) }, 0);
        std::mem::forget(leader);
        std::mem::forget(descendant);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            let leader_gone = unsafe { libc::kill(pgid, 0) } != 0;
            let descendant_gone = unsafe { libc::kill(dpid, 0) } != 0;
            if leader_gone && descendant_gone {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("group {pgid} still had a zombie after the background reaper");
    }
}
