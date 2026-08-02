use std::fs::{self, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

pub fn write_atomic_if_changed(
    path: &Path,
    contents: &[u8],
    permissions_source: Option<&Path>,
) -> io::Result<bool> {
    match fs::read(path) {
        Ok(current) if current == contents => return Ok(false),
        Ok(_) | Err(_) => {}
    }

    write_atomic(path, contents, permissions_source)?;
    Ok(true)
}

pub fn write_atomic(
    path: &Path,
    contents: &[u8],
    permissions_source: Option<&Path>,
) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidInput,
            format!("atomic file {} has no parent directory", path.display()),
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                format!("atomic file {} has no file name", path.display()),
            )
        })?;
    fs::create_dir_all(parent)?;
    let temporary = unique_sibling_path(parent, file_name);

    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;

        if let Some(source) = permissions_source {
            fs::set_permissions(&temporary, fs::metadata(source)?.permissions())?;
        }
        fs::rename(&temporary, path)?;
        sync_directory(parent)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn unique_sibling_path(parent: &Path, file_name: &str) -> PathBuf {
    let sequence = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        ".{file_name}.boxctl-{}-{sequence}.tmp",
        process::id()
    ))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn atomically_replaces_only_when_contents_change() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("boxctl-atomic-file-{nonce}"));
        let path = root.join("state/snapshot");

        assert!(write_atomic_if_changed(&path, b"first", None).unwrap());
        assert!(!write_atomic_if_changed(&path, b"first", None).unwrap());
        assert!(write_atomic_if_changed(&path, b"second", None).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"second");

        fs::remove_dir_all(root).unwrap();
    }
}
