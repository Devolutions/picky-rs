use std::os::raw::{c_char, c_int};

/// Picky return status
#[repr(C)]
pub enum status {
    /// Operation ended successfully.
    Success = 0,

    /// If a function returns this value,
    /// a detailed error message can be retrieved using `picky_error_message_utf*`.
    Failure = -1,
}

/// cbindgen:ignore
impl ffi_helpers::Nullable for status {
    const NULL: Self = Self::Failure;

    fn is_null(&self) -> bool {
        matches!(self, Self::Failure)
    }
}

/// Clear the LAST_ERROR static.
#[no_mangle]
pub extern "C" fn picky_clear_last_error() {
    ffi_helpers::error_handling::clear_last_error()
}

/// Get the length of the last error message in bytes when encoded as UTF-8, including the trailing null.
#[no_mangle]
pub extern "C" fn picky_last_error_length_utf8() -> c_int {
    ffi_helpers::error_handling::last_error_length()
}

/// Get the length of the last error message in bytes when encoded as UTF-16, including the trailing null.
#[no_mangle]
pub extern "C" fn picky_last_error_length_utf16() -> c_int {
    ffi_helpers::error_handling::last_error_length_utf16()
}

/// Peek at the most recent error and write its error message into the provided buffer as a UTF-8 encoded string.
///
/// Returns the number of bytes written, or `-1` if there was an error.
#[no_mangle]
pub unsafe extern "C" fn picky_error_message_utf8(buf: *mut c_char, buf_sz: c_int) -> c_int {
    ffi_helpers::error_handling::error_message_utf8(buf, buf_sz)
}

/// Peek at the most recent error and write its error message into the provided buffer as a UTF-16 encoded string.
///
/// Returns the number of elements written, or `-1` if there was an error.
#[no_mangle]
pub unsafe extern "C" fn picky_error_message_utf16(buf: *mut u16, buf_sz: c_int) -> c_int {
    ffi_helpers::error_handling::error_message_utf16(buf, buf_sz)
}
