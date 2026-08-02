use std::io;

#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::fd::AsRawFd;

#[cfg(unix)]
pub fn flock_exclusive(file: &File, nonblocking: bool) -> io::Result<()> {
    let operation = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    let result = unsafe { libc::flock(file.as_raw_fd(), operation) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
pub fn flock_exclusive(_file: &std::fs::File, _nonblocking: bool) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub fn send_signal(pid: i32, signal: i32) -> io::Result<()> {
    let result = unsafe { libc::kill(pid, signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
pub fn send_signal(pid: i32, signal: i32) -> io::Result<()> {
    std::process::Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .status()
        .map(|_| ())
}

#[cfg(unix)]
pub fn local_time(seconds: i64) -> Option<LocalTime> {
    let timestamp = seconds as libc::time_t;
    let mut time = std::mem::MaybeUninit::<libc::tm>::uninit();
    let result = unsafe { libc::localtime_r(&timestamp, time.as_mut_ptr()) };
    (!result.is_null()).then(|| {
        let time = unsafe { time.assume_init() };
        LocalTime {
            year: time.tm_year + 1900,
            month: time.tm_mon + 1,
            day: time.tm_mday,
            hour: time.tm_hour,
            minute: time.tm_min,
            second: time.tm_sec,
        }
    })
}

#[cfg(not(unix))]
pub fn local_time(_seconds: i64) -> Option<LocalTime> {
    None
}

pub struct LocalTime {
    pub year: i32,
    pub month: i32,
    pub day: i32,
    pub hour: i32,
    pub minute: i32,
    pub second: i32,
}
