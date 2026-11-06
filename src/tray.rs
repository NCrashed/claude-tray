use crate::status::Status;
use crate::{autostart, icon, root, tunnel};
use ksni::menu::{CheckmarkItem, RadioGroup, RadioItem, StandardItem};
use std::path::PathBuf;
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum Action {
    Connect(tunnel::Tunnel),
    Disconnect,
    OpenBrowser,
    SetAutostart(bool),
    Quit,
}

pub struct ClaudeTray {
    pub status: Status,
    pub tunnels_dir: PathBuf,
    pub action_tx: mpsc::UnboundedSender<Action>,
}

impl ksni::Tray for ClaudeTray {
    fn id(&self) -> String {
        "claude-tunnel".into()
    }

    fn title(&self) -> String {
        "Claude Tunnel".into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![icon::status_icon(&self.status)]
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: self.status.label(),
            description: "Claude Code is fail-closed inside a network namespace".into(),
            ..Default::default()
        }
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        let tunnels = tunnel::discover(&self.tunnels_dir);
        let mut items: Vec<ksni::MenuItem<Self>> = vec![StandardItem {
            label: self.status.label(),
            enabled: false,
            ..Default::default()
        }
        .into()];
        items.push(ksni::MenuItem::Separator);

        if tunnels.is_empty() {
            items.push(
                StandardItem {
                    label: "No tunnel configs".into(),
                    enabled: false,
                    ..Default::default()
                }
                .into(),
            );
        } else {
            let selected = self
                .status
                .active_name()
                .and_then(|active| tunnels.iter().position(|item| item.name == active))
                .unwrap_or(usize::MAX);
            let choices = tunnels
                .iter()
                .map(|item| RadioItem {
                    label: item.name.clone(),
                    ..Default::default()
                })
                .collect();
            items.push(
                RadioGroup {
                    selected,
                    options: choices,
                    select: Box::new(move |tray: &mut Self, index| {
                        if let Some(item) = tunnels.get(index) {
                            let _ = tray.action_tx.send(Action::Connect(item.clone()));
                        }
                    }),
                }
                .into(),
            );
        }

        if root::is_up() {
            items.push(
                StandardItem {
                    label: "Открыть браузер".into(),
                    activate: Box::new(|tray: &mut Self| {
                        let _ = tray.action_tx.send(Action::OpenBrowser);
                    }),
                    ..Default::default()
                }
                .into(),
            );
            items.push(
                StandardItem {
                    label: "Disconnect (Claude stays offline)".into(),
                    activate: Box::new(|tray: &mut Self| {
                        let _ = tray.action_tx.send(Action::Disconnect);
                    }),
                    ..Default::default()
                }
                .into(),
            );
        } else {
            items.push(
                StandardItem {
                    label: "Открыть браузер".into(),
                    enabled: false,
                    ..Default::default()
                }
                .into(),
            );
        }
        items.push(ksni::MenuItem::Separator);
        items.push(
            CheckmarkItem {
                label: "Autostart".into(),
                checked: autostart::is_enabled(),
                activate: Box::new(|tray: &mut Self| {
                    let _ = tray
                        .action_tx
                        .send(Action::SetAutostart(!autostart::is_enabled()));
                }),
                ..Default::default()
            }
            .into(),
        );
        items.push(
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|tray: &mut Self| {
                    let _ = tray.action_tx.send(Action::Quit);
                }),
                ..Default::default()
            }
            .into(),
        );
        items
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnected_label_explicitly_says_traffic_is_blocked() {
        assert_eq!(Status::Disconnected.label(), "Protected: offline");
    }

    #[test]
    fn menu_is_available_without_tunnel_configs() {
        use ksni::Tray;
        let dir = tempfile::tempdir().unwrap();
        let (action_tx, _actions) = mpsc::unbounded_channel();
        let tray = ClaudeTray {
            status: Status::Disconnected,
            tunnels_dir: dir.path().to_path_buf(),
            action_tx,
        };

        let menu = tray.menu();
        assert!(!menu.is_empty());
        assert!(matches!(
            &menu[0],
            ksni::MenuItem::Standard(item) if !item.enabled
        ));
        assert!(matches!(
            &menu[2],
            ksni::MenuItem::Standard(item) if !item.enabled
        ));
        assert!(menu.iter().any(|item| matches!(
            item,
            ksni::MenuItem::Standard(item) if item.label == "Открыть браузер" && !item.enabled
        )));
    }
}
