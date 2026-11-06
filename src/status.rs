#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Disconnected,
    Connecting(String),
    Connected(String),
    Failed(String),
}

impl Status {
    pub fn label(&self) -> String {
        match self {
            Self::Disconnected => "Protected: offline".into(),
            Self::Connecting(name) => format!("Connecting {name}…"),
            Self::Connected(name) => format!("Protected via {name}"),
            Self::Failed(message) => format!("Error: {message}"),
        }
    }

    pub fn active_name(&self) -> Option<&str> {
        match self {
            Self::Connecting(name) | Self::Connected(name) => Some(name),
            Self::Disconnected | Self::Failed(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_and_active_names_cover_every_state() {
        assert_eq!(Status::Disconnected.label(), "Protected: offline");
        assert_eq!(Status::Connecting("x".into()).active_name(), Some("x"));
        assert_eq!(Status::Connected("y".into()).active_name(), Some("y"));
        assert_eq!(Status::Failed("no".into()).active_name(), None);
    }
}
