use anyhow::Context;
use std::os::raw::c_int;

macro_rules! none_check {
    ($opt:expr) => {
        none_check!($opt, ::ffi_helpers::Nullable::NULL)
    };
    ($opt:expr, $err_value:expr) => {
        if let Some(val) = $opt {
            val
        } else {
            ::ffi_helpers::error_handling::update_last_error(::ffi_helpers::NullPointer);
            return $err_value;
        }
    };
}

macro_rules! char_ptr_to_str {
    ($c_str_ptr:expr) => {{
        use ::anyhow::Context;
        ::ffi_helpers::null_pointer_check!($c_str_ptr);
        let input = ::std::ffi::CStr::from_ptr($c_str_ptr);
        ::ffi_helpers::catch_panic!(input
            .to_str()
            .context(concat!("bad ", stringify!($c_str_ptr), " argument")))
    }};
}

macro_rules! ptr_to_buffer {
    (@u8 $u8_ptr:expr, $size:expr) => {{
        ptr_to_buffer!(@impl from_raw_parts, $u8_ptr, $size)
    }};
    (@u8 $u8_ptr:expr, $size:expr, $err_value:expr) => {{
        ptr_to_buffer!(@impl from_raw_parts, $u8_ptr, $size, $err_value)
    }};
    (mut @u8 $u8_ptr_mut:expr, $size:expr) => {{
        ptr_to_buffer!(@impl from_raw_parts_mut, $u8_ptr_mut, $size)
    }};
    (mut @u8 $u8_ptr_mut:expr, $size:expr, $err_value:expr) => {{
        ptr_to_buffer!(@impl from_raw_parts_mut, $u8_ptr_mut, $size, $err_value)
    }};
    (mut @c_char $c_str_ptr_mut:expr, $size:expr) => {{
        ptr_to_buffer!(@impl from_raw_parts_mut, $c_str_ptr_mut as *mut u8, $size)
    }};
    (mut @c_char $c_str_ptr_mut:expr, $size:expr, $err_value:expr) => {{
        ptr_to_buffer!(@impl from_raw_parts_mut, $c_str_ptr_mut as *mut u8, $size, $err_value)
    }};
    (@impl $slice_method:ident, $ptr:expr, $size:expr) => {{
        ptr_to_buffer!(@impl $slice_method, $ptr, $size, ::ffi_helpers::Nullable::NULL)
    }};
    (@impl $slice_method:ident, $ptr:expr, $size:expr, $err_value:expr) => {{
        null_pointer_check!($ptr, $err_value);
        let size = ::ffi_helpers::catch_panic!(
            usize::try_from($size).context(concat!("invalid size parameter ", stringify!($size)))
        );
        ::core::slice::$slice_method($ptr, size)
    }};
}

/// Returns the number of bytes written, or `-1` if there was an error.
pub(crate) fn copy_str_to_c(msg: impl AsRef<[u8]>, buffer: &mut [u8]) -> c_int {
    let msg = msg.as_ref();
    copy_str_to_c_impl(buffer, msg)
}

fn copy_str_to_c_impl(buffer: &mut [u8], msg: &[u8]) -> c_int {
    fn wrapped_impl(buffer: &mut [u8], msg: &[u8]) -> anyhow::Result<c_int> {
        if msg.len() + 1 > buffer.len() {
            anyhow::bail!("buffer too small");
        }

        buffer[..msg.len()].copy_from_slice(msg);
        // Add a trailing null just to be safe
        buffer[msg.len()] = 0;

        c_int::try_from(msg.len() + 1).context("invalid buffer size")
    }

    match wrapped_impl(buffer, msg) {
        Ok(len) => len,
        Err(e) => {
            ffi_helpers::update_last_error(e);
            -1
        }
    }
}
