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

macro_rules! err_check {
    ($opt:expr) => {
        err_check!($opt, ::ffi_helpers::Nullable::NULL)
    };
    ($opt:expr, $err_value:expr) => {
        match $opt {
            Ok(val) => val,
            Err(e) => {
                ::ffi_helpers::error_handling::update_last_error(e);
                return $err_value;
            }
        }
    };
}

macro_rules! char_ptr_to_str {
    ($c_str_ptr:expr) => {{
        use ::anyhow::Context;

        ::ffi_helpers::null_pointer_check!($c_str_ptr);
        let input = ::std::ffi::CStr::from_ptr($c_str_ptr);
        err_check!(input.to_str().context(concat!("bad parameter ", stringify!($c_str_ptr))))
    }};
    ($c_str_ptr:expr, $max_size:expr) => {{
        use ::anyhow::Context;

        // SAFETY: we check for the nul terminator byte presence.
        // We also know there is no interior nul byte because we stop at the first nul byte.
        // We do not put it directly in an unsafe block because we can't check for pointer
        // validity which should be checked by caller.

        ::ffi_helpers::null_pointer_check!($c_str_ptr);
        let buffer = ptr_to_buffer!(@c_char $c_str_ptr, $max_size);
        let index = buffer
            .iter()
            .position(|&v| v == 0)
            .context(concat!("nul-byte not found in parameter ", stringify!($c_str_ptr)));
        let nul_byte_index = err_check!(index);
        let input = ::std::ffi::CStr::from_bytes_with_nul_unchecked(&buffer[..=nul_byte_index]);
        err_check!(input.to_str().context(concat!("bad parameter ", stringify!($c_str_ptr))))
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
    (@c_char $c_str_ptr:expr, $size:expr) => {{
        ptr_to_buffer!(@impl from_raw_parts, $c_str_ptr as *const u8, $size)
    }};
    (@c_char $c_str_ptr:expr, $size:expr, $err_value:expr) => {{
        ptr_to_buffer!(@impl from_raw_parts, $c_str_ptr as *const u8, $size, $err_value)
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
        let size = err_check!(usize::try_from($size).context(concat!("invalid size parameter ", stringify!($size))));
        ::core::slice::$slice_method($ptr, size)
    }};
}

pub(crate) fn copy_str_to_c(src: impl AsRef<[u8]>, dst: &mut [u8]) -> anyhow::Result<c_int> {
    copy_str_to_c_impl(src.as_ref(), dst)
}

fn copy_str_to_c_impl(src: &[u8], dst: &mut [u8]) -> anyhow::Result<c_int> {
    let msg_len = src.len() + 1;

    if msg_len > dst.len() {
        anyhow::bail!("buffer too small");
    }

    dst[..src.len()].copy_from_slice(src);
    // Add a trailing null just to be safe
    dst[src.len()] = 0;

    c_int::try_from(msg_len).context("invalid buffer size")
}

pub(crate) fn copy_slice_to_c(src: impl AsRef<[u8]>, dst: &mut [u8]) -> anyhow::Result<c_int> {
    copy_slice_to_c_impl(src.as_ref(), dst)
}

fn copy_slice_to_c_impl(src: &[u8], dst: &mut [u8]) -> anyhow::Result<c_int> {
    let msg_len = src.len();

    if msg_len > dst.len() {
        anyhow::bail!("buffer too small");
    }

    dst[..src.len()].copy_from_slice(src);

    c_int::try_from(msg_len).context("invalid buffer size")
}
