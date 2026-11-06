use std::path::PathBuf;

fn path() -> Option<PathBuf> {
    dirs::config_dir().map(|base| base.join("autostart/claude-tunnel.desktop"))
}

pub fn is_enabled() -> bool {
    path().is_some_and(|path| path.exists())
}

pub fn set_enabled(enabled: bool) -> Result<(), String> {
    path()
        .ok_or_else(|| "cannot locate the autostart directory".to_string())
        .and_then(|path| set_enabled_at(&path, enabled))
}

fn set_enabled_at(path: &std::path::Path, enabled: bool) -> Result<(), String> {
    if enabled {
        crate::executable::installed().and_then(|executable| enable_at(path, &executable))
    } else {
        disable_at(path)
    }
}

fn enable_at(path: &std::path::Path, executable: &std::path::Path) -> Result<(), String> {
    path.parent()
        .ok_or_else(|| "autostart file has no parent directory".to_string())
        .and_then(|parent| {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))
        })
        .and_then(|()| {
            let entry = format!(
                "[Desktop Entry]\nType=Application\nName=Claude Tunnel\nExec={} tray\nIcon=network-vpn\nTerminal=false\n",
                executable.display()
            );
            std::fs::write(path, entry)
                .map_err(|error| format!("cannot write {}: {error}", path.display()))
        })
}

fn disable_at(path: &std::path::Path) -> Result<(), String> {
    std::fs::remove_file(path).or_else(|error| {
        (error.kind() == std::io::ErrorKind::NotFound)
            .then_some(())
            .ok_or_else(|| format!("cannot remove {}: {error}", path.display()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_and_disable_are_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/claude-tunnel.desktop");

        enable_at(&path, std::path::Path::new("/bin/claude-tunnel")).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("Exec=/bin/claude-tunnel tray"));
        disable_at(&path).unwrap();
        disable_at(&path).unwrap();
        set_enabled_at(&path, false).unwrap();
    }
}
