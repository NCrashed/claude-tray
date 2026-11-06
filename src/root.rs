use crate::network::{self, CommandSpec, FIREWALL_CHAIN, HOST_VETH, NAMESPACE, WG_INTERFACE};
use crate::tunnel;
use fs2::FileExt;
use std::ffi::OsString;
use std::fs::Permissions;
use std::io::Read;
use std::net::SocketAddrV4;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const RUNTIME_DIR: &str = "/run/claude-tunnel";
const RUNTIME_CONFIG: &str = "/run/claude-tunnel/ct-wg.conf";
const ENDPOINT_STATE: &str = "/run/claude-tunnel/endpoint";
const NETNS_ETC: &str = "/etc/netns/claude-code";
const LOCK_FILE: &str = "/run/claude-tunnel.lock";
const ROOT_UID: u32 = 0;

pub fn up(config_path: &Path) -> Result<(), String> {
    require_root().and_then(|()| up_as_root(config_path))
}

pub fn down() -> Result<(), String> {
    require_root().and_then(|()| {
        acquire_lock().map(|_lock| {
            down_internal();
        })
    })
}

fn up_as_root(config_path: &Path) -> Result<(), String> {
    acquire_lock()
        .and_then(|_lock| read_tunnel(config_path).and_then(|validated| replace_tunnel(&validated)))
}

fn read_tunnel(config_path: &Path) -> Result<tunnel::ValidatedTunnel, String> {
    std::fs::read_to_string(config_path)
        .map_err(|error| format!("cannot read {}: {error}", config_path.display()))
        .and_then(|contents| tunnel::validate(&contents))
}

fn replace_tunnel(validated: &tunnel::ValidatedTunnel) -> Result<(), String> {
    down_internal();
    write_runtime_files(validated).and_then(|()| run_setup_plan(validated.endpoint))
}

fn run_setup_plan(endpoint: SocketAddrV4) -> Result<(), String> {
    let result = network::setup_commands(endpoint, RUNTIME_CONFIG)
        .iter()
        .try_for_each(run_checked);
    if result.is_err() {
        down_internal();
    }
    result
}

pub fn is_up() -> bool {
    // SAFETY: geteuid has no preconditions and only reads process credentials.
    let effective_uid = unsafe { libc::geteuid() };
    is_up_for(effective_uid, active_endpoint().is_some(), interface_is_up)
}

fn is_up_for<F>(effective_uid: u32, has_root_state: bool, probe_interface: F) -> bool
where
    F: FnOnce() -> bool,
{
    if effective_uid == ROOT_UID {
        probe_interface()
    } else {
        has_root_state
    }
}

fn interface_is_up() -> bool {
    Command::new("ip")
        .args([
            "netns",
            "exec",
            NAMESPACE,
            "ip",
            "link",
            "show",
            WG_INTERFACE,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

pub fn active_endpoint() -> Option<SocketAddrV4> {
    std::fs::read_to_string(ENDPOINT_STATE)
        .ok()?
        .trim()
        .parse()
        .ok()
}

pub fn exec_as_sudo_user(
    uid: u32,
    gid: u32,
    cwd: &Path,
    environment_file: &Path,
    program: &Path,
    arguments: &[OsString],
) -> Result<i32, String> {
    require_root().and_then(|()| {
        verify_sudo_identity(uid, gid).and_then(|()| {
            ensure_tunnel_up().and_then(|()| {
                read_environment_file(environment_file, uid).and_then(|environment| {
                    run_in_namespace(uid, gid, cwd, &environment, program, arguments)
                })
            })
        })
    })
}

fn ensure_tunnel_up() -> Result<(), String> {
    is_up()
        .then_some(())
        .ok_or_else(|| "Claude tunnel is not connected; refusing direct network access".into())
}

fn run_in_namespace(
    uid: u32,
    gid: u32,
    cwd: &Path,
    environment: &[(String, String)],
    program: &Path,
    arguments: &[OsString],
) -> Result<i32, String> {
    let mut command = namespace_command(uid, gid, environment);
    command.arg(program).args(arguments).current_dir(cwd);
    command
        .status()
        .map(|status| status.code().unwrap_or(1))
        .map_err(|error| format!("cannot launch protected application: {error}"))
}

fn namespace_command(uid: u32, gid: u32, environment: &[(String, String)]) -> Command {
    let mut command = Command::new("ip");
    command.args(["netns", "exec", NAMESPACE, "setpriv"]);
    command.arg(format!("--reuid={uid}"));
    command.arg(format!("--regid={gid}"));
    command.args(["--init-groups", "--no-new-privs", "env", "-i"]);
    command.args(
        environment
            .iter()
            .map(|(key, value)| format!("{key}={value}")),
    );
    command
}

fn read_environment_file(path: &Path, uid: u32) -> Result<Vec<(String, String)>, String> {
    validate_environment_path(path, uid).and_then(|()| {
        open_private_file(path, uid).and_then(|mut file| {
            read_environment_bytes(&mut file).and_then(|bytes| {
                let _ = std::fs::remove_file(path);
                parse_environment(&bytes)
            })
        })
    })
}

fn validate_environment_path(path: &Path, uid: u32) -> Result<(), String> {
    let expected_parent = PathBuf::from(format!("/run/user/{uid}/claude-tunnel"));
    (path.parent() == Some(expected_parent.as_path()))
        .then_some(())
        .ok_or_else(|| "environment request is outside the caller runtime directory".into())
}

fn open_private_file(path: &Path, uid: u32) -> Result<std::fs::File, String> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("cannot safely open environment request: {error}"))
        .and_then(|file| validate_private_file(file, uid))
}

fn validate_private_file(file: std::fs::File, uid: u32) -> Result<std::fs::File, String> {
    file.metadata()
        .map_err(|error| format!("cannot inspect environment request: {error}"))
        .and_then(|metadata| {
            let private =
                metadata.is_file() && metadata.uid() == uid && metadata.mode() & 0o077 == 0;
            private.then_some(file).ok_or_else(|| {
                "environment request must be a private regular file owned by the caller".into()
            })
        })
}

fn read_environment_bytes(file: &mut std::fs::File) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map(|_| bytes)
        .map_err(|error| format!("cannot read environment request: {error}"))
}

fn parse_environment(bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let text = std::str::from_utf8(entry)
                .map_err(|_| "environment request is not UTF-8".to_string())?;
            let (key, value) = text
                .split_once('=')
                .ok_or_else(|| "environment request contains an invalid entry".to_string())?;
            if !allowed_environment_key(key) {
                return Err(format!("environment variable {key} is not allowed"));
            }
            Ok((key.to_string(), value.to_string()))
        })
        .collect()
}

pub fn allowed_environment_key(key: &str) -> bool {
    matches!(
        key,
        "HOME"
            | "USER"
            | "LOGNAME"
            | "PATH"
            | "SHELL"
            | "TERM"
            | "COLORTERM"
            | "LANG"
            | "DISPLAY"
            | "WAYLAND_DISPLAY"
            | "XAUTHORITY"
            | "DBUS_SESSION_BUS_ADDRESS"
            | "DESKTOP_STARTUP_ID"
            | "SSH_AUTH_SOCK"
            | "SSL_CERT_FILE"
            | "SSL_CERT_DIR"
    ) || key.starts_with("LC_")
        || key.starts_with("XDG_")
        || key.starts_with("CLAUDE_")
        || key.starts_with("ANTHROPIC_")
        || key.starts_with("NODE_")
}

fn require_root() -> Result<(), String> {
    // SAFETY: geteuid has no preconditions and only reads process credentials.
    (unsafe { libc::geteuid() } == ROOT_UID)
        .then_some(())
        .ok_or_else(|| "privileged command must be run through sudo".to_string())
}

fn acquire_lock() -> Result<std::fs::File, String> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(LOCK_FILE)
        .map_err(|error| format!("cannot open operation lock: {error}"))
        .and_then(|file| {
            file.lock_exclusive()
                .map(|()| file)
                .map_err(|error| format!("cannot lock tunnel operations: {error}"))
        })
}

fn verify_sudo_identity(uid: u32, gid: u32) -> Result<(), String> {
    parse_sudo_id("SUDO_UID").and_then(|sudo_uid| {
        parse_sudo_id("SUDO_GID")
            .and_then(|sudo_gid| validate_sudo_identity((uid, gid), (sudo_uid, sudo_gid)))
    })
}

fn validate_sudo_identity(requested: (u32, u32), actual: (u32, u32)) -> Result<(), String> {
    (requested == actual && requested.0 != 0)
        .then_some(())
        .ok_or_else(|| "requested identity does not match the invoking sudo user".into())
}

fn parse_sudo_id(name: &str) -> Result<u32, String> {
    std::env::var(name)
        .map_err(|_| format!("{name} is missing; invoke this command with sudo"))?
        .parse()
        .map_err(|_| format!("{name} is invalid"))
}

fn write_runtime_files(validated: &tunnel::ValidatedTunnel) -> Result<(), String> {
    create_runtime_dir().and_then(|()| {
        write_runtime_config(validated).and_then(|()| {
            write_endpoint(validated.endpoint)
                .and_then(|()| write_dns_config(&validated.dns_servers))
        })
    })
}

fn create_runtime_dir() -> Result<(), String> {
    std::fs::create_dir_all(RUNTIME_DIR)
        .map_err(|error| format!("cannot create {RUNTIME_DIR}: {error}"))
}

fn write_runtime_config(validated: &tunnel::ValidatedTunnel) -> Result<(), String> {
    std::fs::write(RUNTIME_CONFIG, &validated.normalized_config)
        .map_err(|error| format!("cannot write runtime tunnel config: {error}"))
        .and_then(|()| {
            std::fs::set_permissions(RUNTIME_CONFIG, Permissions::from_mode(0o600))
                .map_err(|error| format!("cannot protect runtime tunnel config: {error}"))
        })
}

fn write_endpoint(endpoint: SocketAddrV4) -> Result<(), String> {
    std::fs::write(ENDPOINT_STATE, endpoint.to_string())
        .map_err(|error| format!("cannot persist tunnel endpoint: {error}"))
}

fn write_dns_config(dns_servers: &[std::net::IpAddr]) -> Result<(), String> {
    std::fs::create_dir_all(NETNS_ETC)
        .map_err(|error| format!("cannot create {NETNS_ETC}: {error}"))
        .and_then(|()| {
            let resolv_conf = dns_servers
                .iter()
                .map(|server| format!("nameserver {server}\n"))
                .collect::<String>();
            std::fs::write(format!("{NETNS_ETC}/resolv.conf"), resolv_conf)
                .map_err(|error| format!("cannot write namespace DNS config: {error}"))
        })
}

fn down_internal() {
    active_endpoint()
        .into_iter()
        .flat_map(cleanup_firewall_commands)
        .for_each(|command| run_ignoring_status(&command));
    run_ignoring_status(&CommandSpec {
        program: "ip",
        args: ["netns", "delete", NAMESPACE]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    });
    for path in [
        RUNTIME_CONFIG,
        ENDPOINT_STATE,
        &format!("{NETNS_ETC}/resolv.conf"),
    ] {
        let _ = std::fs::remove_file(path);
    }
    let _ = std::fs::remove_dir(NETNS_ETC);
}

fn cleanup_firewall_commands(endpoint: SocketAddrV4) -> Vec<CommandSpec> {
    let ip = endpoint.ip().to_string();
    let port = endpoint.port().to_string();
    vec![
        command(
            "iptables",
            &[
                "-D",
                "FORWARD",
                "-o",
                HOST_VETH,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
        ),
        command(
            "iptables",
            &["-D", "FORWARD", "-i", HOST_VETH, "-j", FIREWALL_CHAIN],
        ),
        command(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                "10.203.0.2/32",
                "-d",
                &ip,
                "-p",
                "udp",
                "--dport",
                &port,
                "-j",
                "MASQUERADE",
            ],
        ),
        command("iptables", &["-F", FIREWALL_CHAIN]),
        command("iptables", &["-X", FIREWALL_CHAIN]),
    ]
}

fn command(program: &'static str, args: &[&str]) -> CommandSpec {
    CommandSpec {
        program,
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
    }
}

fn run_checked(spec: &CommandSpec) -> Result<(), String> {
    Command::new(spec.program)
        .args(&spec.args)
        .output()
        .map_err(|error| format!("cannot run {}: {error}", display_command(spec)))
        .and_then(|output| evaluate_output(spec, output))
}

fn evaluate_output(spec: &CommandSpec, output: std::process::Output) -> Result<(), String> {
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} failed: {}",
            display_command(spec),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn run_ignoring_status(spec: &CommandSpec) {
    let _ = Command::new(spec.program)
        .args(&spec.args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn display_command(spec: &CommandSpec) -> String {
    format!("{} {}", spec.program, spec.args.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_exactly_reverses_all_firewall_rules() {
        let commands = cleanup_firewall_commands("192.0.2.1:51820".parse().unwrap());

        assert_eq!(commands.len(), 5);
        assert!(commands[..3]
            .iter()
            .all(|item| item.args.contains(&"-D".to_string())));
        assert!(commands
            .iter()
            .any(|item| item.args.contains(&"-X".to_string())));
        assert!(commands
            .iter()
            .any(|item| item.args.contains(&"MASQUERADE".to_string())));
    }

    #[test]
    fn environment_allowlist_keeps_credentials_but_rejects_loader_injection() {
        assert!(allowed_environment_key("ANTHROPIC_API_KEY"));
        assert!(allowed_environment_key("CLAUDE_CODE_USE_BEDROCK"));
        assert!(allowed_environment_key("XDG_RUNTIME_DIR"));
        for key in [
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XAUTHORITY",
            "DBUS_SESSION_BUS_ADDRESS",
            "DESKTOP_STARTUP_ID",
        ] {
            assert!(allowed_environment_key(key));
        }
        assert!(!allowed_environment_key("LD_PRELOAD"));
        assert!(!allowed_environment_key("BASH_ENV"));
    }

    #[test]
    fn parses_only_allowlisted_environment_entries() {
        let parsed = parse_environment(b"HOME=/home/user\0ANTHROPIC_API_KEY=secret\0").unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parse_environment(b"LD_PRELOAD=evil\0").is_err());
        assert!(parse_environment(b"broken\0").is_err());
        assert!(parse_environment(&[0xff, 0]).is_err());
    }

    #[test]
    fn private_file_check_uses_owner_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("environment");
        std::fs::write(&path, "HOME=/home/user\0").unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        let uid = std::fs::metadata(&path).unwrap().uid();

        assert!(open_private_file(&path, uid).is_ok());
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        assert!(open_private_file(&path, uid).is_err());
    }

    #[test]
    fn sudo_identity_must_match_and_must_not_be_root() {
        assert!(validate_sudo_identity((1000, 100), (1000, 100)).is_ok());
        assert!(validate_sudo_identity((1, 1), (1, 1)).is_ok());
        assert!(validate_sudo_identity((1000, 100), (1001, 100)).is_err());
        assert!(validate_sudo_identity((0, 0), (0, 0)).is_err());
        assert!(validate_sudo_identity((0, 100), (0, 100)).is_err());
        assert!(require_root().is_err());
    }

    #[test]
    fn checked_commands_report_success_and_stderr() {
        assert!(run_checked(&command("true", &[])).is_ok());
        assert!(run_checked(&command("false", &[])).is_err());
    }

    #[test]
    fn unprivileged_status_uses_root_owned_state_but_root_probes_the_interface() {
        assert!(is_up_for(1000, true, || false));
        assert!(!is_up_for(1000, false, || true));
        assert!(is_up_for(ROOT_UID, false, || true));
        assert!(!is_up_for(ROOT_UID, true, || false));
    }
}
