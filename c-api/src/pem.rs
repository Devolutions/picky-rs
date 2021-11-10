use crate::error::status;
use crate::helper::copy_str_to_c;
use anyhow::Context;
use picky::pem::*;
use std::os::raw::{c_char, c_int};

/// Opaque type for picky PEM object.
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct pem_t(Pem<'static>);

/// Parses a PEM-encoded string representation into a PEM object.
#[no_mangle]
pub unsafe extern "C" fn picky_pem_parse(input: *const c_char) -> Option<Box<pem_t>> {
    let input = char_ptr_to_str!(input);
    let pem = catch_panic!(picky::pem::parse_pem(input).context("bad PEM"));
    Some(Box::new(pem_t(pem)))
}

/// Creates a PEM object with a copy of the data.
#[no_mangle]
pub unsafe extern "C" fn picky_pem_new(data: *const u8, data_sz: c_int, label: *const c_char) -> Option<Box<pem_t>> {
    let data = ptr_to_buffer!(@u8 data, data_sz);
    let label = char_ptr_to_str!(label);

    // Build an owned `Pem` object
    let data = data.to_owned();
    let pem = Pem::new(label, data);

    Some(Box::new(pem_t(pem)))
}

/// Encodes to PEM string without copying the payload.
#[no_mangle]
pub unsafe extern "C" fn picky_encode_pem(
    data: *const u8,
    data_sz: c_int,
    label: *const c_char,
    repr: *mut c_char,
    repr_sz: c_int,
) -> status {
    let data = ptr_to_buffer!(@u8 data, data_sz);
    let label = char_ptr_to_str!(label);
    let buffer = ptr_to_buffer!(mut @c_char repr, repr_sz);

    let pem = Pem::new(label, data);
    copy_str_to_c(pem.to_string(), buffer);

    status::Success
}

/// Copy raw data contained in the PEM object.
///
/// Returns the number of bytes written, or `-1` if there was an error.
#[no_mangle]
pub unsafe extern "C" fn picky_pem_data(this: Option<&pem_t>, data: *mut u8, data_sz: c_int) -> c_int {
    let this = none_check!(this, -1);
    let buffer = ptr_to_buffer!(mut @u8 data, data_sz, -1);
    copy_str_to_c(this.0.data(), buffer)
}

/// Copy the label associated to the data contained in the PEM object.
///
/// Returns the number of bytes written, or `-1` if there was an error.
#[no_mangle]
pub unsafe extern "C" fn picky_pem_label(this: Option<&pem_t>, label: *mut c_char, label_sz: c_int) -> c_int {
    let this = none_check!(this, -1);
    let buffer = ptr_to_buffer!(mut @c_char label, label_sz, -1);
    copy_str_to_c(this.0.label(), buffer)
}

/// Encodes PEM object to the PEM string representation.
///
/// Returns the number of bytes written, or `-1` if there was an error.
#[no_mangle]
pub unsafe extern "C" fn picky_pem_to_string(this: Option<&pem_t>, repr: *mut c_char, repr_sz: c_int) -> c_int {
    let this = none_check!(this, -1);
    let buffer = ptr_to_buffer!(mut @c_char repr, repr_sz, -1);
    copy_str_to_c(this.0.to_string(), buffer)
}

/// Frees memory for this PEM object.
#[no_mangle]
pub extern "C" fn picky_pem_drop(_: Option<Box<pem_t>>) {}

/// Returns a cloned version of this PEM object.
#[no_mangle]
pub extern "C" fn picky_pem_clone(src: Option<&pem_t>) -> Option<Box<pem_t>> {
    src.map(|src| Box::new(Clone::clone(src)))
}
