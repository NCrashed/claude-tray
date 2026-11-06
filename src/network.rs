use std::net::SocketAddrV4;

pub const NAMESPACE: &str = "claude-code";
pub const HOST_VETH: &str = "ct-host";
pub const NS_VETH: &str = "ct-ns";
pub const WG_INTERFACE: &str = "ct-wg";
pub const FIREWALL_CHAIN: &str = "CT_GUARD";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: &'static str,
    pub args: Vec<String>,
}

impl CommandSpec {
    fn new(program: &'static str, args: &[&str]) -> Self {
        Self {
            program,
            args: args.iter().map(|value| (*value).to_string()).collect(),
        }
    }
}

pub fn setup_commands(endpoint: SocketAddrV4, runtime_config: &str) -> Vec<CommandSpec> {
    let endpoint_ip = endpoint.ip().to_string();
    let endpoint_port = endpoint.port().to_string();
    vec![
        CommandSpec::new("ip", &["netns", "add", NAMESPACE]),
        CommandSpec::new(
            "ip",
            &[
                "link", "add", HOST_VETH, "type", "veth", "peer", "name", NS_VETH,
            ],
        ),
        CommandSpec::new("ip", &["link", "set", NS_VETH, "netns", NAMESPACE]),
        CommandSpec::new("ip", &["address", "add", "10.203.0.1/30", "dev", HOST_VETH]),
        CommandSpec::new("ip", &["link", "set", HOST_VETH, "up"]),
        CommandSpec::new(
            "ip",
            &["netns", "exec", NAMESPACE, "ip", "link", "set", "lo", "up"],
        ),
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                NAMESPACE,
                "ip",
                "address",
                "add",
                "10.203.0.2/30",
                "dev",
                NS_VETH,
            ],
        ),
        CommandSpec::new(
            "ip",
            &[
                "netns", "exec", NAMESPACE, "ip", "link", "set", NS_VETH, "up",
            ],
        ),
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                NAMESPACE,
                "ip",
                "route",
                "add",
                "default",
                "via",
                "10.203.0.1",
            ],
        ),
        CommandSpec::new(
            "sysctl",
            &["-q", "-w", "net.ipv4.conf.ct-host.forwarding=1"],
        ),
        CommandSpec::new("iptables", &["-N", FIREWALL_CHAIN]),
        CommandSpec::new(
            "iptables",
            &[
                "-I",
                "FORWARD",
                "1",
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
        CommandSpec::new(
            "iptables",
            &[
                "-A",
                FIREWALL_CHAIN,
                "-d",
                &endpoint_ip,
                "-p",
                "udp",
                "--dport",
                &endpoint_port,
                "-j",
                "ACCEPT",
            ],
        ),
        CommandSpec::new("iptables", &["-A", FIREWALL_CHAIN, "-j", "DROP"]),
        CommandSpec::new(
            "iptables",
            &["-I", "FORWARD", "1", "-i", HOST_VETH, "-j", FIREWALL_CHAIN],
        ),
        CommandSpec::new(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "10.203.0.2/32",
                "-d",
                &endpoint_ip,
                "-p",
                "udp",
                "--dport",
                &endpoint_port,
                "-j",
                "MASQUERADE",
            ],
        ),
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                NAMESPACE,
                "awg-quick",
                "up",
                runtime_config,
            ],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_switch_jumps_first_to_a_default_deny_chain() {
        let commands = setup_commands(
            "192.0.2.1:51820".parse().unwrap(),
            "/run/claude-tunnel/ct-wg.conf",
        );
        let firewall: Vec<_> = commands
            .iter()
            .filter(|command| command.program == "iptables")
            .collect();

        assert_eq!(firewall.len(), 6);
        assert_eq!(firewall[0].args, ["-N", FIREWALL_CHAIN]);
        assert!(firewall[2]
            .args
            .windows(2)
            .any(|pair| pair == ["-d", "192.0.2.1"]));
        assert!(firewall[2]
            .args
            .windows(2)
            .any(|pair| pair == ["--dport", "51820"]));
        assert_eq!(
            &firewall[3].args[firewall[3].args.len() - 2..],
            ["-j", "DROP"]
        );
        assert_eq!(firewall[4].args.first().map(String::as_str), Some("-I"));
        assert!(firewall[5].args.contains(&"MASQUERADE".to_string()));
    }

    #[test]
    fn wireguard_starts_only_after_drop_rule_exists() {
        let commands = setup_commands("192.0.2.1:51820".parse().unwrap(), "/runtime.conf");
        let drop_index = commands
            .iter()
            .position(|command| command.args.last().map(String::as_str) == Some("DROP"))
            .unwrap();
        let tunnel_index = commands
            .iter()
            .position(|command| command.args.iter().any(|arg| arg == "awg-quick"))
            .unwrap();

        assert!(drop_index < tunnel_index);
    }
}
