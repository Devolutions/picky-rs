macro_rules! err_check {
    ($expr:expr) => {{
        match $expr {
            Ok(v) => v,
            Err(e) => return Err(Box::new($crate::error::ffi::PickyError::from(e.to_string()))).into(),
        }
    }};
}

macro_rules! err_check_from {
    ($expr:expr) => {{
        match $expr {
            Ok(v) => v,
            Err(e) => return Err(Box::new($crate::error::ffi::PickyError::from(e))).into(),
        }
    }};
}
