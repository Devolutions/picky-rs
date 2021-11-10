use std::os::raw::{c_char, c_int};

#[repr(C)]
pub enum status {
    Success = 0,
    Failure = -1,
}

/// cbindgen:ignore
impl ffi_helpers::Nullable for status {
    const NULL: Self = Self::Failure;

    fn is_null(&self) -> bool {
        matches!(self, Self::Failure)
    }
}

#[no_mangle]
pub extern "C" fn picky_clear_last_error() {
    ffi_helpers::error_handling::clear_last_error()
}

#[no_mangle]
pub extern "C" fn picky_last_error_length_utf8() -> c_int {
    ffi_helpers::error_handling::last_error_length()
}

#[no_mangle]
pub extern "C" fn picky_last_error_length_utf16() -> c_int {
    ffi_helpers::error_handling::last_error_length_utf16()
}

#[no_mangle]
pub unsafe extern "C" fn picky_error_message_utf8(buf: *mut c_char, buf_sz: c_int) -> c_int {
    ffi_helpers::error_handling::error_message_utf8(buf, buf_sz)
}

#[no_mangle]
pub unsafe extern "C" fn picky_error_message_utf16(buf: *mut u16, buf_sz: c_int) -> c_int {
    ffi_helpers::error_handling::error_message_utf16(buf, buf_sz)
}
