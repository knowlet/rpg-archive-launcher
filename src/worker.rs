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
    let (status, mut data) = match result {
        Ok(data) => (0, data),
        Err(error) => (1, error.into_bytes()),
    };
    if data.len() >= MAX_RESPONSE {
        return Err(io::Error::other("worker response exceeds limit"));
    }
    data.insert(0, status);
    frame_write(output, &data, MAX_RESPONSE)
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
            let path: Option<String> =
                serde_json::from_slice(&request).map_err(|e| e.to_string())?;
            let result = match path {
                Some(p) => archive.read(&p),
                None => archive.ensure_source_unchanged().map(|()| Vec::new()),
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
    watchdog: Option<thread::JoinHandle<()>>,
    watch_stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    watch_failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
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
        let mut child = Command::new(executable)
            .arg("__decoder-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
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
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        if self.failed {
            return Err("decoder worker is unavailable".into());
        }
        let result = self.exchange_inner(request);
        if result.is_err() {
            self.stop();
        }
        result
    }
    fn check_watchdog(&self, start: Instant) -> Result<()> {
        if start.elapsed() >= TIMEOUT {
            return Err("decoder worker wall timeout".into());
        }
        if self.watch_failed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("decoder worker RSS supervision failed or exceeded limit".into());
        }
        Ok(())
    }
    fn exchange_inner(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        if request.len() > MAX_REQUEST {
            return Err("worker request exceeds limit".into());
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
                .ok_or("worker closed")?
                .write(&frame[sent..])
            {
                Ok(0) => return Err("worker pipe closed".into()),
                Ok(n) => sent += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        loop {
            self.check_watchdog(start)?;
            match self.replies.recv_timeout(POLL) {
                Ok(reply) => {
                    let mut data = reply.map_err(|e| e.to_string())?;
                    if data.is_empty() {
                        return Err("empty worker response".into());
                    }
                    let status = data.remove(0);
                    return match status {
                        0 => Ok(data),
                        1 => Err(String::from_utf8_lossy(&data).into_owned()),
                        _ => Err("invalid worker response status".into()),
                    };
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => return Err("decoder worker EOF".into()),
            }
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
            let _ = reader.join();
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
}
