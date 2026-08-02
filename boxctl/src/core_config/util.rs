use super::*;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

pub(super) fn write_atomic_runtime_config(
    source: &Path,
    runtime: &Path,
    text: &str,
) -> Result<bool> {
    match fs::read_to_string(runtime) {
        Ok(current) if current == text => return Ok(false),
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "read runtime config {} failed: {err}",
                runtime.display()
            ));
        }
    }

    crate::atomic_file::write_atomic_if_changed(runtime, text.as_bytes(), Some(source))
        .map_err(|err| format!("write runtime config {} failed: {err}", runtime.display()))
}

pub(super) fn find_sing_box_inbound<'a>(
    inbounds: &'a [Value],
    inbound_type: &str,
) -> Option<&'a Value> {
    inbounds
        .iter()
        .find(|value| json_field_string(value, "type").as_deref() == Some(inbound_type))
}

pub(super) fn json_field_string(value: &Value, key: &str) -> Option<String> {
    value.as_object()?.get(key)?.as_str().map(ToOwned::to_owned)
}

pub(super) fn json_field_bool(value: &Value, key: &str) -> Option<bool> {
    value.as_object()?.get(key)?.as_bool()
}

pub(super) fn normalized_text_values(values: &[String]) -> Vec<String> {
    let mut values: Vec<String> = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    values.sort();
    values.dedup();
    values
}

pub(super) fn empty_default<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.trim().is_empty() {
        default
    } else {
        value.trim()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn writes_only_the_runtime_config() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("boxctl-runtime-config-{nonce}"));
        let source = root.join("source.yaml");
        let runtime = root.join("run/state/startup-config");
        let original = "dns:\n  listen: 127.0.0.1:1053\n";
        let generated = "dns:\n  listen: 0.0.0.0:1053\n";

        fs::create_dir_all(&root).unwrap();
        fs::write(&source, original).unwrap();

        assert!(write_atomic_runtime_config(&source, &runtime, generated).unwrap());
        assert_eq!(fs::read_to_string(&source).unwrap(), original);
        assert_eq!(fs::read_to_string(&runtime).unwrap(), generated);
        assert!(!write_atomic_runtime_config(&source, &runtime, generated).unwrap());

        fs::remove_dir_all(root).unwrap();
    }
}
