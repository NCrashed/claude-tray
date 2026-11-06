use std::path::PathBuf;

pub fn installed() -> Result<PathBuf, String> {
    let profile_binary = dirs::home_dir().map(|home| home.join(".nix-profile/bin/claude-tunnel"));
    if let Some(binary) = profile_binary.filter(|path| path.is_file()) {
        return Ok(binary);
    }
    std::env::current_exe().map_err(|error| format!("cannot locate current executable: {error}"))
}

pub fn browser_opener() -> Result<PathBuf, String> {
    let profile_opener =
        dirs::home_dir().map(|home| home.join(".nix-profile/bin/claude-tunnel-browser-opener"));
    if let Some(opener) = profile_opener.filter(|path| path.is_file()) {
        return Ok(opener);
    }
    installed().and_then(|executable| {
        executable
            .parent()
            .map(|directory| directory.join("claude-tunnel-browser-opener"))
            .filter(|path| path.is_file())
            .ok_or_else(|| "cannot locate the protected browser opener".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_profile_binary_is_stable_across_nix_store_updates() {
        if let Some(home) = dirs::home_dir() {
            let expected = home.join(".nix-profile/bin/claude-tunnel");
            if expected.is_file() {
                assert_eq!(installed().unwrap(), expected);
            }
        }
    }

    #[test]
    fn browser_opener_never_falls_back_to_a_system_opener() {
        if let Some(home) = dirs::home_dir() {
            let expected = home.join(".nix-profile/bin/claude-tunnel-browser-opener");
            if expected.is_file() {
                assert_eq!(browser_opener().unwrap(), expected);
            }
        }
    }
}
