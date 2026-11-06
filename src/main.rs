mod autostart;
mod executable;
mod icon;
mod status;
mod tray;

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use claude_tunnel::{config::AppConfig, root, tunnel};
use ksni::TrayMethods;
use status::Status;
use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, ExitCode, Stdio};
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tray::{Action, ClaudeTray};

const SUCCESS: u8 = 0;
const PROTECTED_OFFLINE: u8 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "claude-tunnel",
    about = "Fail-closed WireGuard routing for Claude Code"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Run the tray application.
    Tray,
    /// Run Claude Code inside the protected network namespace.
    Run {
        #[arg(last = true)]
        arguments: Vec<OsString>,
    },
    /// Open a dedicated Chromium profile inside the protected namespace.
    Browser {
        #[arg(last = true)]
        arguments: Vec<OsString>,
    },
    /// Print whether Claude Code has a usable tunnel.
    Status,
    #[command(name = "__open-url", hide = true)]
    OpenUrl { url: OsString },
    #[command(name = "__root", hide = true)]
    Root {
        #[command(subcommand)]
        command: RootCommand,
    },
}

#[derive(Debug, Subcommand)]
enum RootCommand {
    Up {
        config: PathBuf,
    },
    Down,
    Exec {
        #[arg(long)]
        uid: u32,
        #[arg(long)]
        gid: u32,
        #[arg(long)]
        cwd: PathBuf,
        #[arg(long)]
        environment_file: PathBuf,
        #[arg(long)]
        program: PathBuf,
        #[arg(last = true)]
        arguments: Vec<OsString>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt::init();
    exit_code(run().await)
}

fn exit_code(result: Result<u8, String>) -> ExitCode {
    match result {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            error!("{message}");
            eprintln!("claude-tunnel: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<u8, String> {
    let cli = Cli::parse();
    dispatch(cli.command.unwrap_or(CliCommand::Tray)).await
}

async fn dispatch(command: CliCommand) -> Result<u8, String> {
    match command {
        CliCommand::Root { command } => run_root(command),
        user_command => dispatch_user(user_command).await,
    }
}

async fn dispatch_user(command: CliCommand) -> Result<u8, String> {
    match command {
        CliCommand::Tray => run_tray_command().await,
        CliCommand::Run { arguments } => run_claude_command(&arguments),
        CliCommand::Browser { arguments } => run_browser_command(&arguments),
        CliCommand::OpenUrl { url } => spawn_protected_browser(&url),
        CliCommand::Status => report_status(),
        CliCommand::Root { .. } => Err("root command crossed the user dispatch boundary".into()),
    }
}

fn run_claude_command(arguments: &[OsString]) -> Result<u8, String> {
    AppConfig::load().and_then(|config| run_claude(&config, arguments))
}

fn run_browser_command(arguments: &[OsString]) -> Result<u8, String> {
    browser_url(arguments)
        .and_then(|url| AppConfig::load().and_then(|config| run_browser(&config, &url)))
}

fn spawn_protected_browser(url: &OsStr) -> Result<u8, String> {
    let url = validate_browser_url(url)?;
    StdCommand::new(executable::installed()?)
        .arg("browser")
        .arg("--")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| SUCCESS)
        .map_err(|error| format!("cannot launch protected browser opener: {error}"))
}

fn report_status() -> Result<u8, String> {
    if root::is_up() {
        println!("connected");
        Ok(SUCCESS)
    } else {
        println!("offline (direct access blocked)");
        Ok(PROTECTED_OFFLINE)
    }
}

async fn run_tray_command() -> Result<u8, String> {
    let config = AppConfig::load()?;
    run_tray(config).await.map(|()| SUCCESS)
}

fn run_root(command: RootCommand) -> Result<u8, String> {
    match command {
        RootCommand::Up { config } => root::up(&config).map(|()| SUCCESS),
        RootCommand::Down => root::down().map(|()| SUCCESS),
        RootCommand::Exec {
            uid,
            gid,
            cwd,
            environment_file,
            program,
            arguments,
        } => root::exec_as_sudo_user(uid, gid, &cwd, &environment_file, &program, &arguments)
            .map(exit_status_byte),
    }
}

fn exit_status_byte(code: i32) -> u8 {
    code.clamp(0, u8::MAX as i32) as u8
}

async fn run_tray(config: AppConfig) -> Result<(), String> {
    let (tray, actions) = prepare_tray(&config)?;
    run_prepared_tray(config, tray, actions).await
}

fn prepare_tray(
    config: &AppConfig,
) -> Result<(ClaudeTray, mpsc::UnboundedReceiver<Action>), String> {
    if !config.tunnels_dir.is_dir() {
        std::fs::create_dir_all(&config.tunnels_dir)
            .map_err(|error| format!("cannot create {}: {error}", config.tunnels_dir.display()))?;
    }
    let (action_tx, action_rx) = mpsc::unbounded_channel();
    let status = detect_status(&config.tunnels_dir);
    Ok((
        ClaudeTray {
            status,
            tunnels_dir: config.tunnels_dir.clone(),
            action_tx,
        },
        action_rx,
    ))
}

async fn run_prepared_tray(
    config: AppConfig,
    tray: ClaudeTray,
    action_rx: mpsc::UnboundedReceiver<Action>,
) -> Result<(), String> {
    let handle = tray
        .spawn()
        .await
        .map_err(|error| format!("cannot create tray icon: {error}"))?;

    let action_handle = handle.clone();
    let runtime_config = config.clone();
    tokio::spawn(handle_actions(action_rx, action_handle, runtime_config));
    tokio::spawn(poll_status(
        handle,
        config.tunnels_dir,
        Duration::from_secs(config.poll_interval_secs.max(1)),
    ));
    std::future::pending::<()>().await;
    Ok(())
}

async fn handle_actions(
    actions: mpsc::UnboundedReceiver<Action>,
    handle: ksni::Handle<ClaudeTray>,
    config: AppConfig,
) {
    handle_actions_with_runtime(actions, &DesktopRuntime { handle, config }).await;
}

#[async_trait]
trait ActionRuntime {
    async fn connect(&self, target: tunnel::Tunnel);
    async fn disconnect(&self);
    fn open_browser(&self);
    fn set_autostart(&self, enabled: bool);
    fn quit(&self);
}

struct DesktopRuntime {
    handle: ksni::Handle<ClaudeTray>,
    config: AppConfig,
}

async fn handle_actions_with_runtime<R: ActionRuntime>(
    mut actions: mpsc::UnboundedReceiver<Action>,
    runtime: &R,
) {
    while let Some(action) = actions.recv().await {
        dispatch_action(action, runtime).await;
    }
}

async fn dispatch_action<R: ActionRuntime>(action: Action, runtime: &R) {
    match action {
        Action::Connect(target) => runtime.connect(target).await,
        Action::Disconnect => runtime.disconnect().await,
        Action::OpenBrowser => runtime.open_browser(),
        Action::SetAutostart(enabled) => runtime.set_autostart(enabled),
        Action::Quit => runtime.quit(),
    }
}

#[async_trait]
impl ActionRuntime for DesktopRuntime {
    async fn connect(&self, target: tunnel::Tunnel) {
        let name = target.name.clone();
        self.handle
            .update(move |tray| tray.status = Status::Connecting(name))
            .await;
        let result = privileged(&[OsStr::new("up"), target.path.as_os_str()]).await;
        let status = connection_status(target.name, result);
        self.handle.update(move |tray| tray.status = status).await;
    }

    async fn disconnect(&self) {
        let result = privileged(&[OsStr::new("down")]).await;
        let status = disconnection_status(result);
        self.handle.update(move |tray| tray.status = status).await;
    }

    fn open_browser(&self) {
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(message) = run_browser(&config, "https://claude.ai/login") {
                error!("{message}");
            }
        });
    }

    fn set_autostart(&self, enabled: bool) {
        autostart::set_enabled(enabled).unwrap_or_else(|message| warn!("{message}"));
    }

    fn quit(&self) {
        std::process::exit(0);
    }
}

fn connection_status(name: String, result: Result<(), String>) -> Status {
    result
        .map(|()| Status::Connected(name))
        .unwrap_or_else(Status::Failed)
}

fn disconnection_status(result: Result<(), String>) -> Status {
    result
        .map(|()| Status::Disconnected)
        .unwrap_or_else(Status::Failed)
}

async fn poll_status(handle: ksni::Handle<ClaudeTray>, tunnels_dir: PathBuf, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        let status = detect_status(&tunnels_dir);
        handle
            .update(move |tray| merge_status(&mut tray.status, status))
            .await;
    }
}

fn merge_status(current: &mut Status, observed: Status) {
    if !matches!(current, Status::Connecting(_)) && *current != observed {
        *current = observed;
    }
}

fn detect_status(tunnels_dir: &Path) -> Status {
    status_for_endpoint(
        tunnels_dir,
        root::is_up().then(root::active_endpoint).flatten(),
    )
}

fn status_for_endpoint(tunnels_dir: &Path, endpoint: Option<std::net::SocketAddrV4>) -> Status {
    match endpoint {
        Some(endpoint) => Status::Connected(
            matching_tunnel_name(tunnels_dir, endpoint).unwrap_or_else(|| "active tunnel".into()),
        ),
        None => Status::Disconnected,
    }
}

fn matching_tunnel_name(tunnels_dir: &Path, endpoint: std::net::SocketAddrV4) -> Option<String> {
    tunnel::discover(tunnels_dir).into_iter().find_map(|item| {
        let contents = std::fs::read_to_string(&item.path).ok()?;
        (tunnel::validate(&contents).ok()?.endpoint == endpoint).then_some(item.name)
    })
}

async fn privileged(arguments: &[&OsStr]) -> Result<(), String> {
    let executable = executable::installed()?;
    invoke_privileged(executable, arguments).await
}

async fn invoke_privileged(executable: PathBuf, arguments: &[&OsStr]) -> Result<(), String> {
    Command::new("sudo")
        .arg("-n")
        .arg(executable)
        .arg("__root")
        .args(arguments)
        .output()
        .await
        .map_err(|error| format!("cannot invoke privileged helper: {error}"))
        .and_then(privileged_output)
}

fn privileged_output(output: std::process::Output) -> Result<(), String> {
    if output.status.success() {
        Ok(())
    } else {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if message.is_empty() {
            "privileged helper failed; check sudoers configuration".into()
        } else {
            message
        })
    }
}

fn run_claude(config: &AppConfig, arguments: &[OsString]) -> Result<u8, String> {
    ensure_tunnel_available()
        .and_then(|()| protected_claude_environment())
        .and_then(|environment| prepare_launch(&config.claude_binary, &environment))
        .and_then(|launch| execute_protected(launch, arguments))
}

fn run_browser(config: &AppConfig, url: &str) -> Result<u8, String> {
    ensure_tunnel_available()
        .and_then(|()| create_browser_profile(&config.browser_profile_dir))
        .and_then(|()| prepare_launch(&config.browser_binary, &protected_timezone_environment()))
        .and_then(|launch| execute_protected(launch, &browser_arguments(config, url)))
}

fn create_browser_profile(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path)
        .map_err(|error| format!("cannot create browser profile {}: {error}", path.display()))
}

fn browser_arguments(config: &AppConfig, url: &str) -> [OsString; 4] {
    let mut profile = OsString::from("--user-data-dir=");
    profile.push(&config.browser_profile_dir);
    [
        profile,
        OsString::from("--no-first-run"),
        OsString::from("--new-window"),
        OsString::from(url),
    ]
}

fn browser_url(arguments: &[OsString]) -> Result<String, String> {
    match arguments {
        [] => Ok("https://claude.ai/login".into()),
        [url] => validate_browser_url(url),
        _ => Err("browser accepts at most one URL".into()),
    }
}

fn validate_browser_url(url: &OsStr) -> Result<String, String> {
    let url = url
        .to_str()
        .ok_or_else(|| "browser URL is not valid UTF-8".to_string())?;
    ((url.starts_with("https://") || url.starts_with("http://"))
        && !url.chars().any(char::is_control))
    .then(|| url.to_string())
    .ok_or_else(|| "browser opener only accepts http:// or https:// URLs".into())
}

fn protected_timezone_environment() -> Vec<(String, String)> {
    vec![("TZ".into(), "UTC".into())]
}

fn protected_claude_environment() -> Result<Vec<(String, String)>, String> {
    executable::browser_opener().and_then(|opener| {
        opener
            .into_os_string()
            .into_string()
            .map(protected_claude_environment_with)
            .map_err(|_| "protected browser opener path is not valid UTF-8".into())
    })
}

fn protected_claude_environment_with(browser_opener: String) -> Vec<(String, String)> {
    let mut environment = protected_timezone_environment();
    environment.push(("BROWSER".into(), browser_opener));
    environment
}

fn ensure_tunnel_available() -> Result<(), String> {
    root::is_up()
        .then_some(())
        .ok_or_else(|| "tunnel is offline; refusing to launch protected application".into())
}

struct Launch {
    executable: PathBuf,
    program: PathBuf,
    environment_file: PathBuf,
    cwd: PathBuf,
    uid: u32,
    gid: u32,
}

fn prepare_launch(program: &Path, environment: &[(String, String)]) -> Result<Launch, String> {
    resolve_program(program).and_then(|program| {
        numeric_id("-u").and_then(|uid| {
            numeric_id("-g").and_then(|gid| {
                launch_paths(uid, environment).map(|(executable, environment_file, cwd)| Launch {
                    executable,
                    program,
                    environment_file,
                    cwd,
                    uid,
                    gid,
                })
            })
        })
    })
}

fn launch_paths(
    uid: u32,
    environment: &[(String, String)],
) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    std::env::current_dir()
        .map_err(|error| format!("cannot read cwd: {error}"))
        .and_then(|cwd| {
            write_environment_request(uid, environment).and_then(|environment_file| {
                executable::installed().map(|executable| (executable, environment_file, cwd))
            })
        })
}

fn execute_protected(launch: Launch, arguments: &[OsString]) -> Result<u8, String> {
    let result = StdCommand::new("sudo")
        .arg("-n")
        .arg(launch.executable)
        .args(["__root", "exec", "--uid"])
        .arg(launch.uid.to_string())
        .arg("--gid")
        .arg(launch.gid.to_string())
        .arg("--cwd")
        .arg(launch.cwd)
        .arg("--environment-file")
        .arg(&launch.environment_file)
        .arg("--program")
        .arg(launch.program)
        .arg("--")
        .args(arguments)
        .status()
        .map(|status| status.code().unwrap_or(1).clamp(0, u8::MAX as i32) as u8)
        .map_err(|error| format!("cannot invoke protected application: {error}"));
    let _ = std::fs::remove_file(launch.environment_file);
    result
}

fn numeric_id(flag: &str) -> Result<u32, String> {
    let output = StdCommand::new("id")
        .arg(flag)
        .output()
        .map_err(|error| format!("cannot run id {flag}: {error}"))?;
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|_| format!("id {flag} returned an invalid number"))
}

fn resolve_program(program: &Path) -> Result<PathBuf, String> {
    if program.components().count() > 1 {
        return program
            .is_file()
            .then(|| program.to_path_buf())
            .ok_or_else(|| format!("Claude binary does not exist: {}", program.display()));
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| format!("cannot find {} in PATH", program.display()))
}

fn write_environment_request(
    uid: u32,
    environment: &[(String, String)],
) -> Result<PathBuf, String> {
    let directory = PathBuf::from(format!("/run/user/{uid}/claude-tunnel"));
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create {}: {error}", directory.display()))
        .and_then(|()| create_environment_file(&directory, environment))
}

fn create_environment_file(
    directory: &Path,
    environment: &[(String, String)],
) -> Result<PathBuf, String> {
    let path = directory.join(format!("env-{}", std::process::id()));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("cannot create environment request: {error}"))
        .and_then(|mut file| write_environment_entries(&mut file, environment))
        .map(|()| path)
}

fn write_environment_entries(
    file: &mut std::fs::File,
    overrides: &[(String, String)],
) -> Result<(), String> {
    let environment = merge_environment(std::env::vars(), overrides)?;
    for (key, value) in environment {
        file.write_all(key.as_bytes())
            .and_then(|()| file.write_all(b"="))
            .and_then(|()| file.write_all(value.as_bytes()))
            .and_then(|()| file.write_all(&[0]))
            .map_err(|error| format!("cannot write environment request: {error}"))?;
    }
    info!("prepared protected Claude environment");
    Ok(())
}

fn merge_environment(
    inherited: impl IntoIterator<Item = (String, String)>,
    overrides: &[(String, String)],
) -> Result<Vec<(String, String)>, String> {
    if let Some((key, _)) = overrides
        .iter()
        .find(|(key, _)| !root::allowed_environment_key(key))
    {
        return Err(format!("environment variable {key} is not allowed"));
    }
    Ok(inherited
        .into_iter()
        .filter(|(key, _)| {
            root::allowed_environment_key(key) && !overrides.iter().any(|(name, _)| name == key)
        })
        .chain(overrides.iter().cloned())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_tunnel_is_reported_as_protected_offline() {
        if !root::is_up() {
            assert_eq!(detect_status(Path::new("/missing")), Status::Disconnected);
            assert!(run_claude(&AppConfig::default(), &[]).is_err());
            assert!(run_browser(&AppConfig::default(), "https://claude.ai/login").is_err());
        }
    }

    #[test]
    fn status_merge_preserves_connecting_state() {
        let mut status = Status::Connecting("sample".into());
        merge_status(&mut status, Status::Disconnected);
        assert!(matches!(status, Status::Connecting(_)));

        let mut status = Status::Connected("sample".into());
        merge_status(&mut status, Status::Disconnected);
        assert_eq!(status, Status::Disconnected);
    }

    #[test]
    fn active_tunnel_name_requires_the_same_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("sample.conf"),
            r#"
[Interface]
PrivateKey = secret
Address = 10.66.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = public
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0
"#,
        )
        .unwrap();

        assert_eq!(
            matching_tunnel_name(dir.path(), "192.0.2.1:51820".parse().unwrap()),
            Some("sample".into())
        );
        assert_eq!(
            matching_tunnel_name(dir.path(), "192.0.2.2:51820".parse().unwrap()),
            None
        );
        assert_eq!(status_for_endpoint(dir.path(), None), Status::Disconnected);
        assert_eq!(
            status_for_endpoint(dir.path(), Some("192.0.2.1:51820".parse().unwrap())),
            Status::Connected("sample".into())
        );
    }

    #[test]
    fn pure_launch_helpers_cover_ids_paths_and_environment() {
        assert!(numeric_id("-u").is_ok());
        assert!(resolve_program(&std::env::current_exe().unwrap()).is_ok());
        assert!(resolve_program(Path::new("true")).is_ok());
        assert!(resolve_program(Path::new("certainly-not-a-real-command")).is_err());
        assert!(executable::installed().unwrap().is_file());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("environment");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let overrides = [("BROWSER".into(), "/protected/opener".into())];
        write_environment_entries(&mut file, &overrides).unwrap();
        let bytes = std::fs::read(path).unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(bytes.last(), Some(&0));
        assert!(bytes
            .windows(b"BROWSER=/protected/opener\0".len())
            .any(|window| window == b"BROWSER=/protected/opener\0"));

        let merged = merge_environment(
            [
                ("HOME".into(), "/home/user".into()),
                ("BROWSER".into(), "/system/opener".into()),
                ("LD_PRELOAD".into(), "evil".into()),
            ],
            &overrides,
        )
        .unwrap();
        assert_eq!(
            merged,
            [
                ("HOME".into(), "/home/user".into()),
                ("BROWSER".into(), "/protected/opener".into()),
            ]
        );
        assert!(merge_environment([], &[("LD_PRELOAD".into(), "evil".into())]).is_err());
    }

    #[test]
    fn tray_preparation_creates_the_tunnel_directory() {
        let dir = tempfile::tempdir().unwrap();
        let config = AppConfig {
            tunnels_dir: dir.path().join("nested/tunnels"),
            ..AppConfig::default()
        };
        let (tray, _actions) = prepare_tray(&config).unwrap();
        assert!(tray.tunnels_dir.is_dir());
    }

    #[tokio::test]
    async fn dispatch_covers_safe_noninteractive_commands() {
        let status = dispatch(CliCommand::Status).await.unwrap();
        assert_eq!(
            status,
            if root::is_up() {
                SUCCESS
            } else {
                PROTECTED_OFFLINE
            }
        );
        if !root::is_up() {
            assert!(dispatch(CliCommand::Root {
                command: RootCommand::Down
            })
            .await
            .is_err());
        }
        if !root::is_up() {
            assert!(dispatch(CliCommand::Run { arguments: vec![] })
                .await
                .is_err());
            assert!(dispatch(CliCommand::Browser { arguments: vec![] })
                .await
                .is_err());
        }
        assert!(dispatch(CliCommand::OpenUrl {
            url: OsString::from("file:///tmp/private")
        })
        .await
        .is_err());
        assert!(dispatch_user(CliCommand::Root {
            command: RootCommand::Down
        })
        .await
        .is_err());
    }

    #[test]
    fn root_dispatch_rejects_every_variant_for_unprivileged_callers() {
        assert!(run_root(RootCommand::Down).is_err());
        assert!(run_root(RootCommand::Up {
            config: PathBuf::from("missing")
        })
        .is_err());
        assert!(run_root(RootCommand::Exec {
            uid: 1000,
            gid: 100,
            cwd: PathBuf::from("/"),
            environment_file: PathBuf::from("missing"),
            program: PathBuf::from("missing"),
            arguments: vec![],
        })
        .is_err());
    }

    #[test]
    fn exit_and_privileged_output_cover_success_and_failure() {
        use std::os::unix::process::ExitStatusExt;
        let output = |status, stderr: &[u8]| std::process::Output {
            status: std::process::ExitStatus::from_raw(status),
            stdout: Vec::new(),
            stderr: stderr.to_vec(),
        };

        let _ = exit_code(Ok(0));
        let _ = exit_code(Err("expected".into()));
        assert!(privileged_output(output(0, b"")).is_ok());
        assert!(privileged_output(output(256, b"denied")).is_err());
        assert!(privileged_output(output(256, b"")).is_err());
        assert_eq!(exit_status_byte(-1), 0);
        assert_eq!(exit_status_byte(0), 0);
        assert_eq!(exit_status_byte(300), u8::MAX);
        assert_eq!(
            connection_status("sample".into(), Ok(())),
            Status::Connected("sample".into())
        );
        assert!(matches!(
            connection_status("sample".into(), Err("no".into())),
            Status::Failed(_)
        ));
        assert_eq!(disconnection_status(Ok(())), Status::Disconnected);
        assert!(matches!(
            disconnection_status(Err("no".into())),
            Status::Failed(_)
        ));
    }

    #[derive(Default)]
    struct FakeRuntime(std::sync::Mutex<Vec<&'static str>>);

    #[async_trait]
    impl ActionRuntime for FakeRuntime {
        async fn connect(&self, _target: tunnel::Tunnel) {
            self.0.lock().unwrap().push("connect");
        }

        async fn disconnect(&self) {
            self.0.lock().unwrap().push("disconnect");
        }

        fn set_autostart(&self, _enabled: bool) {
            self.0.lock().unwrap().push("autostart");
        }

        fn open_browser(&self) {
            self.0.lock().unwrap().push("browser");
        }

        fn quit(&self) {
            self.0.lock().unwrap().push("quit");
        }
    }

    #[tokio::test]
    async fn action_loop_dispatches_every_action() {
        let runtime = FakeRuntime::default();
        let (sender, receiver) = mpsc::unbounded_channel();
        sender
            .send(Action::Connect(tunnel::Tunnel {
                name: "sample".into(),
                path: PathBuf::from("sample.conf"),
            }))
            .unwrap();
        sender.send(Action::Disconnect).unwrap();
        sender.send(Action::OpenBrowser).unwrap();
        sender.send(Action::SetAutostart(true)).unwrap();
        sender.send(Action::Quit).unwrap();
        drop(sender);

        handle_actions_with_runtime(receiver, &runtime).await;

        assert_eq!(
            *runtime.0.lock().unwrap(),
            ["connect", "disconnect", "browser", "autostart", "quit"]
        );
    }

    #[test]
    fn browser_uses_a_dedicated_profile_and_login_page() {
        let config = AppConfig {
            browser_profile_dir: PathBuf::from("/tmp/claude-browser"),
            ..AppConfig::default()
        };

        assert_eq!(
            browser_arguments(&config, "https://console.anthropic.com/oauth"),
            [
                OsString::from("--user-data-dir=/tmp/claude-browser"),
                OsString::from("--no-first-run"),
                OsString::from("--new-window"),
                OsString::from("https://console.anthropic.com/oauth"),
            ]
        );
        assert_eq!(browser_url(&[]).unwrap(), "https://claude.ai/login");
        assert_eq!(
            browser_url(&[OsString::from("http://127.0.0.1/callback")]).unwrap(),
            "http://127.0.0.1/callback"
        );
        assert!(browser_url(&[OsString::from("file:///tmp/private")]).is_err());
        assert!(browser_url(&[OsString::from("--proxy-server=direct://")]).is_err());
        assert!(
            browser_url(&[OsString::from("https://one"), OsString::from("https://two")]).is_err()
        );
    }

    #[test]
    fn protected_processes_always_use_utc() {
        assert_eq!(
            protected_timezone_environment(),
            vec![("TZ".to_string(), "UTC".to_string())]
        );
        assert!(
            protected_claude_environment_with("/protected/opener".into())
                .contains(&("TZ".to_string(), "UTC".to_string()))
        );
    }
}
