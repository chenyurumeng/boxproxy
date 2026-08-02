use crate::config::Config;
use crate::Result;
use std::fs::{self, File, OpenOptions};

pub(super) struct OperationLock {
    _file: File,
}

impl OperationLock {
    pub(super) fn acquire(config: &Config) -> Result<Self> {
        fs::create_dir_all(&config.paths.state)
            .map_err(|err| format!("create state directory failed: {err}"))?;
        let path = config.paths.state.join("control.lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|err| format!("open operation lock {} failed: {err}", path.display()))?;

        // The lock is released automatically when this command exits, including crashes.
        crate::platform::flock_exclusive(&file, false)
            .map_err(|err| format!("acquire operation lock {} failed: {err}", path.display()))?;

        Ok(Self { _file: file })
    }
}
