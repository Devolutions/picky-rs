macro_rules! epoch_until {
    ($sec: expr) => {{
        use std::time::{SystemTime, UNIX_EPOCH};
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("UNIX EPOCH should be in the past")
            .as_secs()
            + $sec)
    }};
}
