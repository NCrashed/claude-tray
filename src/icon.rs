use crate::status::Status;

const SIZE: i32 = 22;
const CLAUDE_ORANGE: (u8, u8, u8) = (0xd9, 0x77, 0x57);

pub fn status_icon(status: &Status) -> ksni::Icon {
    let mut data = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let (alpha, red, green, blue) = pixel(x, y, status);
            data.extend_from_slice(&[alpha, red, green, blue]);
        }
    }
    ksni::Icon {
        width: SIZE,
        height: SIZE,
        data,
    }
}

fn pixel(x: i32, y: i32, status: &Status) -> (u8, u8, u8, u8) {
    let cx = 10;
    let cy = 10;
    let dx = x - cx;
    let dy = y - cy;
    let radius_sq = dx * dx + dy * dy;
    if is_claude_mark(dx, dy, radius_sq) {
        let (red, green, blue) = CLAUDE_ORANGE;
        return (255, red, green, blue);
    }

    if is_badge(x, y) {
        let color = badge_color(status);
        return (255, color.0, color.1, color.2);
    }
    (0, 0, 0, 0)
}

fn is_claude_mark(dx: i32, dy: i32, radius_sq: i32) -> bool {
    let diagonal = (dx - dy).abs() <= 1 || (dx + dy).abs() <= 1;
    let straight = dx.abs() <= 1 || dy.abs() <= 1;
    radius_sq <= 9 || ((straight || diagonal) && radius_sq <= 74)
}

fn is_badge(x: i32, y: i32) -> bool {
    (x - 17).pow(2) + (y - 17).pow(2) <= 16
}

fn badge_color(status: &Status) -> (u8, u8, u8) {
    match status {
        Status::Disconnected => (0xe7, 0x4c, 0x3c),
        Status::Connecting(_) => (0xf3, 0x9c, 0x12),
        Status::Connected(_) => (0x2e, 0xcc, 0x71),
        Status::Failed(_) => (0x9b, 0x59, 0xb6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_mark_and_every_status_badge_are_rendered() {
        let statuses = [
            Status::Disconnected,
            Status::Connecting("sample".into()),
            Status::Connected("sample".into()),
            Status::Failed("failure".into()),
        ];

        let expected = [
            14784318374891841725,
            14477668506372516451,
            10704091679291574241,
            10270853262118223306,
        ];

        for (status, expected_fingerprint) in statuses.into_iter().zip(expected) {
            let icon = status_icon(&status);
            assert_eq!(icon.width, SIZE);
            assert_eq!(icon.height, SIZE);
            assert_eq!(icon.data.len(), (SIZE * SIZE * 4) as usize);
            let fingerprint = icon.data.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
                (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
            });
            assert_eq!(fingerprint, expected_fingerprint);
        }
        assert_eq!(pixel(10, 10, &Status::Disconnected).0, 255);
        assert_eq!(pixel(0, 21, &Status::Disconnected).0, 0);
        assert!(is_claude_mark(2, 5, 9));
        assert!(is_claude_mark(0, 9, 74));
    }
}
