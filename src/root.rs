use crate::network::{
    self, CommandSpec, FIREWALL_CHAIN, HOST_FIREWALL_CHAIN, HOST_VETH, NAMESPACE, WG_INTERFACE,
};
use crate::tunnel;
use fs2::FileExt;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::Permissions;
use std::io::Read;
use std::net::SocketAddrV4;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const RUNTIME_DIR: &str = "/run/claude-tunnel";
const RUNTIME_CONFIG: &str = "/run/claude-tunnel/ct-wg.conf";
const ENDPOINT_STATE: &str = "/run/claude-tunnel/endpoint";
const STEAM_BRIDGE_STATE: &str = "/run/claude-tunnel/steam-bridge";
const NETNS_ETC: &str = "/etc/netns/claude-code";
const UTC_ZONEINFO: &str = "/etc/zoneinfo/UTC";
const LOCK_FILE: &str = "/run/claude-tunnel.lock";
const ROOT_UID: u32 = 0;
const HOST_VETH_ADDRESS: &str = "10.203.0.1";

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

pub fn steam_bridge_up() -> Result<(), String> {
    require_root().and_then(|()| {
        acquire_lock().and_then(|_lock| {
            ensure_tunnel_up()
                .and_then(|()| parse_sudo_id("SUDO_UID").and_then(replace_steam_bridge))
        })
    })
}

pub fn steam_bridge_down() -> Result<(), String> {
    require_root().and_then(|()| {
        acquire_lock().map(|_lock| {
            stop_steam_bridge();
        })
    })
}

pub fn steam_bridge_is_up() -> bool {
    is_up()
        && std::fs::read_to_string(STEAM_BRIDGE_STATE)
            .ok()
            .is_some_and(|state| steam_bridge_state_is_live(&state, process_exists))
}

fn replace_steam_bridge(uid: u32) -> Result<(), String> {
    discover_steam_loopback_ports(Path::new("/proc"), uid)
        .and_then(require_steam_ports)
        .and_then(|ports| {
            ensure_host_guard()?;
            stop_steam_bridge();
            start_steam_bridge(&ports)
        })
}

fn require_steam_ports(ports: Vec<u16>) -> Result<Vec<u16>, String> {
    (!ports.is_empty()).then_some(ports).ok_or_else(|| {
        "Steam is not listening on any IPv4 loopback ports; start Steam first".into()
    })
}

fn ensure_host_guard() -> Result<(), String> {
    let jump = command(
        "iptables",
        &["-C", "INPUT", "-i", HOST_VETH, "-j", HOST_FIREWALL_CHAIN],
    );
    run_ignoring_status(&command("iptables", &["-N", HOST_FIREWALL_CHAIN]));
    let drop = command("iptables", &["-C", HOST_FIREWALL_CHAIN, "-j", "DROP"]);
    ensure_firewall_rule(
        &drop,
        &command("iptables", &["-A", HOST_FIREWALL_CHAIN, "-j", "DROP"]),
    )?;
    ensure_firewall_rule(
        &jump,
        &command(
            "iptables",
            &[
                "-I",
                "INPUT",
                "1",
                "-i",
                HOST_VETH,
                "-j",
                HOST_FIREWALL_CHAIN,
            ],
        ),
    )
}

fn ensure_firewall_rule(check: &CommandSpec, install: &CommandSpec) -> Result<(), String> {
    if command_succeeds(check) {
        Ok(())
    } else {
        run_checked(install)
    }
}

fn discover_steam_loopback_ports(proc_root: &Path, uid: u32) -> Result<Vec<u16>, String> {
    let entries = std::fs::read_dir(proc_root)
        .map_err(|error| format!("cannot inspect running processes: {error}"))?;
    let mut ports = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if entry.file_name().to_string_lossy().parse::<u32>().is_err()
            || !entry.metadata().is_ok_and(|metadata| metadata.uid() == uid)
            || std::fs::read_to_string(path.join("comm"))
                .map(|comm| comm.trim() != "steam")
                .unwrap_or(true)
        {
            continue;
        }
        let owned = owned_socket_inodes(&path.join("fd"));
        if let Ok(table) = std::fs::read_to_string(path.join("net/tcp")) {
            ports.extend(steam_loopback_ports(&table, &owned));
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn owned_socket_inodes(fd_dir: &Path) -> HashSet<u64> {
    std::fs::read_dir(fd_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .filter_map(|target| {
            target
                .to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse()
                .ok()
        })
        .collect()
}

fn steam_loopback_ports(table: &str, owned: &HashSet<u64>) -> Vec<u16> {
    let mut ports = table
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            let (address, port) = fields.get(1)?.split_once(':')?;
            let listening = *fields.get(3)? == "0A";
            let inode = fields.get(9)?.parse::<u64>().ok()?;
            (listening && address == "0100007F" && owned.contains(&inode))
                .then(|| u16::from_str_radix(port, 16).ok())
                .flatten()
        })
        .collect::<Vec<_>>();
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn start_steam_bridge(ports: &[u16]) -> Result<(), String> {
    spawn_steam_proxies(ports)
        .and_then(verify_started_steam_proxies)
        .and_then(|children| allow_steam_proxy_ports(ports, children))
        .and_then(|children| persist_steam_bridge(ports, children))
}

fn verify_started_steam_proxies(mut children: Vec<Child>) -> Result<Vec<Child>, String> {
    std::thread::sleep(Duration::from_millis(100));
    verify_steam_proxies(&mut children)
        .inspect_err(|_| terminate_proxy_children(&children))
        .map(|()| children)
}

fn allow_steam_proxy_ports(ports: &[u16], children: Vec<Child>) -> Result<Vec<Child>, String> {
    install_steam_firewall_rules(ports)
        .inspect_err(|_| {
            remove_steam_firewall_rules(ports);
            terminate_proxy_children(&children);
        })
        .map(|()| children)
}

fn persist_steam_bridge(ports: &[u16], children: Vec<Child>) -> Result<(), String> {
    let state = ports
        .iter()
        .map(|port| format!("port={port}\n"))
        .chain(children.iter().map(|child| format!("pid={}\n", child.id())))
        .collect::<String>();
    if let Err(error) = write_steam_bridge_state(&state) {
        remove_steam_firewall_rules(ports);
        terminate_proxy_children(&children);
        return Err(error);
    }
    Ok(())
}

fn spawn_steam_proxies(ports: &[u16]) -> Result<Vec<Child>, String> {
    let mut children = Vec::new();
    let result = ports
        .iter()
        .flat_map(|port| [(false, *port), (true, *port)])
        .try_for_each(|(in_namespace, port)| {
            spawn_steam_proxy(in_namespace, port).map(|child| children.push(child))
        });
    result.inspect_err(|_| {
        terminate_proxy_children(&children);
    })?;
    Ok(children)
}

fn verify_steam_proxies(children: &mut [Child]) -> Result<(), String> {
    children
        .iter_mut()
        .find_map(|child| {
            child
                .try_wait()
                .ok()
                .flatten()
                .map(|status| (child.id(), status))
        })
        .map(|(pid, status)| {
            Err(format!(
                "Steam IPC proxy {pid} exited during startup: {status}"
            ))
        })
        .unwrap_or(Ok(()))
}

fn install_steam_firewall_rules(ports: &[u16]) -> Result<(), String> {
    ports
        .iter()
        .try_for_each(|port| run_checked(&steam_firewall_command("-I", *port)))
}

fn spawn_steam_proxy(in_namespace: bool, port: u16) -> Result<Child, String> {
    steam_proxy_command(in_namespace, port)
        .spawn()
        .map_err(|error| format!("cannot start Steam IPC proxy for port {port}: {error}"))
}

fn steam_proxy_command(in_namespace: bool, port: u16) -> Command {
    let (bind, target, namespace) = if in_namespace {
        ("127.0.0.1", HOST_VETH_ADDRESS, Some(NAMESPACE))
    } else {
        (HOST_VETH_ADDRESS, "127.0.0.1", None)
    };
    let listener = format!("TCP4-LISTEN:{port},bind={bind},reuseaddr,fork");
    let target = format!("TCP4:{target}:{port}");
    let mut command = if let Some(namespace) = namespace {
        let mut command = Command::new("ip");
        command.args(["netns", "exec", namespace, "socat"]);
        command
    } else {
        Command::new("socat")
    };
    command
        .args([listener, target])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    command
}

fn write_steam_bridge_state(state: &str) -> Result<(), String> {
    std::fs::write(STEAM_BRIDGE_STATE, state)
        .map_err(|error| format!("cannot persist Steam IPC bridge state: {error}"))
        .and_then(|()| {
            std::fs::set_permissions(STEAM_BRIDGE_STATE, Permissions::from_mode(0o644))
                .map_err(|error| format!("cannot protect Steam IPC bridge state: {error}"))
        })
}

fn stop_steam_bridge() {
    if let Ok(state) = std::fs::read_to_string(STEAM_BRIDGE_STATE) {
        let ports = steam_bridge_state_values(&state, "port")
            .into_iter()
            .filter_map(|port| u16::try_from(port).ok())
            .collect::<Vec<_>>();
        remove_steam_firewall_rules(&ports);
        let pids = steam_bridge_state_values(&state, "pid");
        terminate_proxy_groups(&pids, libc::SIGTERM);
        std::thread::sleep(Duration::from_millis(50));
        terminate_proxy_groups(&pids, libc::SIGKILL);
    }
    let _ = std::fs::remove_file(STEAM_BRIDGE_STATE);
}

fn steam_firewall_command(operation: &'static str, port: u16) -> CommandSpec {
    let position = (operation == "-I").then_some("1");
    let port = port.to_string();
    let mut args = vec![operation, HOST_FIREWALL_CHAIN];
    args.extend(position);
    args.extend([
        "-s",
        "10.203.0.2/32",
        "-d",
        "10.203.0.1/32",
        "-p",
        "tcp",
        "--dport",
        &port,
        "-j",
        "ACCEPT",
    ]);
    command("iptables", &args)
}

fn remove_steam_firewall_rules(ports: &[u16]) {
    for port in ports {
        run_ignoring_status(&steam_firewall_command("-D", *port));
    }
}

fn terminate_proxy_children(children: &[Child]) {
    let pids = children.iter().map(Child::id).collect::<Vec<_>>();
    terminate_proxy_groups(&pids, libc::SIGTERM);
}

fn terminate_proxy_groups(pids: &[u32], signal: i32) {
    for pid in pids {
        // SAFETY: negative PIDs target only the process groups created for our proxy leaders.
        let _ = unsafe { libc::kill(-(*pid as i32), signal) };
    }
}

fn process_exists(pid: u32) -> bool {
    PathBuf::from(format!("/proc/{pid}")).exists()
}

fn steam_bridge_state_values(state: &str, key: &str) -> Vec<u32> {
    state
        .lines()
        .filter_map(|line| line.strip_prefix(&format!("{key}="))?.parse().ok())
        .collect()
}

fn steam_bridge_state_is_live(state: &str, process_is_live: impl Fn(u32) -> bool) -> bool {
    let ports = steam_bridge_state_values(state, "port");
    let pids = steam_bridge_state_values(state, "pid");
    !ports.is_empty() && pids.len() == ports.len() * 2 && pids.into_iter().all(process_is_live)
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
            | "BROWSER"
            | "TZ"
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
                .and_then(|()| {
                    write_localtime_config_at(Path::new(NETNS_ETC), Path::new(UTC_ZONEINFO))
                })
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

fn write_localtime_config_at(netns_etc: &Path, zoneinfo: &Path) -> Result<(), String> {
    std::fs::create_dir_all(netns_etc)
        .map_err(|error| format!("cannot create {}: {error}", netns_etc.display()))
        .and_then(|()| {
            std::fs::copy(zoneinfo, netns_etc.join("localtime"))
                .map(|_| ())
                .map_err(|error| format!("cannot install protected UTC localtime: {error}"))
        })
}

fn down_internal() {
    stop_steam_bridge();
    active_endpoint()
        .into_iter()
        .flat_map(cleanup_firewall_commands)
        .for_each(|command| run_ignoring_status(&command));
    namespace_cleanup_commands()
        .iter()
        .for_each(run_ignoring_status);
    for path in [
        RUNTIME_CONFIG,
        ENDPOINT_STATE,
        &format!("{NETNS_ETC}/resolv.conf"),
        &format!("{NETNS_ETC}/localtime"),
    ] {
        let _ = std::fs::remove_file(path);
    }
    let _ = std::fs::remove_dir(NETNS_ETC);
}

fn namespace_cleanup_commands() -> [CommandSpec; 2] {
    [
        command("ip", &["netns", "delete", NAMESPACE]),
        command("ip", &["link", "delete", HOST_VETH]),
    ]
}

fn cleanup_firewall_commands(endpoint: SocketAddrV4) -> Vec<CommandSpec> {
    let ip = endpoint.ip().to_string();
    let port = endpoint.port().to_string();
    vec![
        command(
            "iptables",
            &["-D", "INPUT", "-i", HOST_VETH, "-j", HOST_FIREWALL_CHAIN],
        ),
        command("iptables", &["-F", HOST_FIREWALL_CHAIN]),
        command("iptables", &["-X", HOST_FIREWALL_CHAIN]),
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

fn command_succeeds(spec: &CommandSpec) -> bool {
    Command::new(spec.program)
        .args(&spec.args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
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

        assert_eq!(commands.len(), 8);
        assert_eq!(
            commands
                .iter()
                .filter(|item| item.args.contains(&"-D".to_string()))
                .count(),
            4
        );
        assert!(commands
            .iter()
            .any(|item| item.args.contains(&"-X".to_string())));
        assert!(commands
            .iter()
            .any(|item| item.args.contains(&"MASQUERADE".to_string())));
    }

    #[test]
    fn cleanup_removes_an_orphaned_host_veth_after_a_partial_setup() {
        let commands = namespace_cleanup_commands();

        assert_eq!(commands[0], command("ip", &["netns", "delete", NAMESPACE]));
        assert_eq!(commands[1], command("ip", &["link", "delete", HOST_VETH]));
    }

    #[test]
    fn environment_allowlist_keeps_credentials_but_rejects_loader_injection() {
        assert!(allowed_environment_key("ANTHROPIC_API_KEY"));
        assert!(allowed_environment_key("CLAUDE_CODE_USE_BEDROCK"));
        assert!(allowed_environment_key("XDG_RUNTIME_DIR"));
        assert!(allowed_environment_key("BROWSER"));
        assert!(allowed_environment_key("TZ"));
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
    fn namespace_localtime_is_an_utc_zoneinfo_copy() {
        let dir = tempfile::tempdir().unwrap();
        let zoneinfo = dir.path().join("UTC");
        let netns_etc = dir.path().join("etc");
        std::fs::write(&zoneinfo, b"fake UTC zoneinfo").unwrap();

        write_localtime_config_at(&netns_etc, &zoneinfo).unwrap();

        assert_eq!(
            std::fs::read(netns_etc.join("localtime")).unwrap(),
            b"fake UTC zoneinfo"
        );
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

    #[test]
    fn steam_bridge_selects_only_owned_ipv4_loopback_listeners() {
        let sockets = r#"
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:DFFF 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 46118195 1 0000000000000000 100 0 0 10 0
   1: 00000000:699C 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 46118196 1 0000000000000000 100 0 0 10 0
   2: 0100007F:B56D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 46121282 1 0000000000000000 100 0 0 10 0
   3: 0100007F:B519 0100007F:DFFF 01 00000000:00000000 00:00000000 00000000  1000        0 46121291 1 0000000000000000 100 0 0 10 0
   4: 0100007F:CAFE 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99999999 1 0000000000000000 100 0 0 10 0
"#;
        let owned = [46_118_195_u64, 46_121_282_u64].into_iter().collect();

        assert_eq!(steam_loopback_ports(sockets, &owned), vec![46_445, 57_343]);
    }

    #[test]
    fn steam_bridge_discovers_only_the_users_steam_process() {
        use std::os::unix::fs::symlink;

        let proc_root = tempfile::tempdir().unwrap();
        let steam = proc_root.path().join("1234");
        std::fs::create_dir_all(steam.join("fd")).unwrap();
        std::fs::create_dir_all(steam.join("net")).unwrap();
        std::fs::write(steam.join("comm"), "steam\n").unwrap();
        symlink("socket:[46118195]", steam.join("fd/7")).unwrap();
        std::fs::write(
            steam.join("net/tcp"),
            "0: 0100007F:DFFF 00000000:0000 0A 0:0 00:0 0 1000 0 46118195\n",
        )
        .unwrap();
        let other = proc_root.path().join("5678");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("comm"), "not-steam\n").unwrap();

        // SAFETY: getuid has no preconditions and only reads process credentials.
        let uid = unsafe { libc::getuid() };
        assert_eq!(
            discover_steam_loopback_ports(proc_root.path(), uid).unwrap(),
            vec![57_343]
        );
    }

    #[test]
    fn steam_bridge_requires_at_least_one_discovered_port() {
        assert!(require_steam_ports(vec![]).is_err());
        assert_eq!(require_steam_ports(vec![46_445]).unwrap(), vec![46_445]);
    }

    #[test]
    fn steam_proxy_commands_bind_only_expected_bridge_addresses() {
        let host = steam_proxy_command(false, 46_445);
        assert_eq!(host.get_program(), "socat");
        assert!(host
            .get_args()
            .any(|arg| arg == "TCP4-LISTEN:46445,bind=10.203.0.1,reuseaddr,fork"));

        let namespace = steam_proxy_command(true, 46_445);
        assert_eq!(namespace.get_program(), "ip");
        assert!(namespace
            .get_args()
            .any(|arg| arg == "TCP4-LISTEN:46445,bind=127.0.0.1,reuseaddr,fork"));
        assert!(namespace
            .get_args()
            .any(|arg| arg == "TCP4:10.203.0.1:46445"));
    }

    #[test]
    fn steam_bridge_state_requires_every_proxy_process() {
        let state = "port=46445\npid=101\npid=102\n";

        assert!(steam_bridge_state_is_live(state, |pid| pid == 101 || pid == 102));
        assert!(!steam_bridge_state_is_live(state, |pid| pid == 101));
        assert!(!steam_bridge_state_is_live("port=46445\n", |_| true));
        assert!(!steam_bridge_state_is_live("pid=101\n", |_| true));
    }
}
