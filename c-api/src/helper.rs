macro_rules! err_check {
    ($expr:expr) => {{
        match $expr {
            Ok(v) => v,
            Err(e) => return Err(Box::new($crate::error::ffi::PickyError(e.to_string()))).into(),
        }
    }};
}
