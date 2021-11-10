use crate::error::status;
use crate::helper::{copy_slice_to_c, copy_str_to_c};
use anyhow::Context;
use picky::pem::*;
use std::os::raw::{c_char, c_int};

/// Opaque type for picky PEM object.
#[allow(non_camel_case_types)]
#[derive(Clone)]
pub struct pem_t {
    inner: Pem<'static>,
}

/// Parses a PEM-encoded string representation into a PEM object.
#[no_mangle]
pub unsafe extern "C" fn picky_pem_parse(input: *const c_char, input_sz: c_int) -> Option<Box<pem_t>> {
    let input = char_ptr_to_str!(input, input_sz);
    let pem = catch_panic!(picky::pem::parse_pem(input).context("bad PEM"));
    Some(Box::new(pem_t { inner: pem }))
}

/// Creates a PEM object with a copy of the data.
#[no_mangle]
pub unsafe extern "C" fn picky_pem_new(
    data: *const u8,
    data_sz: c_int,
    label: *const c_char,
    label_sz: c_int,
) -> Option<Box<pem_t>> {
    let data = ptr_to_buffer!(@u8 data, data_sz);
    let label = char_ptr_to_str!(label, label_sz);

    // Build an owned `Pem` object
    let data = data.to_owned();
    let pem = Pem::new(label, data);

    Some(Box::new(pem_t { inner: pem }))
}

/// Encodes to PEM string without copying the payload.
#[no_mangle]
pub unsafe extern "C" fn picky_encode_pem(
    data: *const u8,
    data_sz: c_int,
    label: *const c_char,
    label_sz: c_int,
    repr: *mut c_char,
    repr_sz: c_int,
) -> status {
    let data = ptr_to_buffer!(@u8 data, data_sz);
    let label = char_ptr_to_str!(label, label_sz);
    let buffer = ptr_to_buffer!(mut @c_char repr, repr_sz);

    let pem = Pem::new(label, data);
    err_check!(copy_str_to_c(pem.to_string(), buffer));

    status::Success
}

/// Get the length of the pem data in bytes.
///
/// Returns the number of required bytes, or `-1` if there was an error.
#[no_mangle]
pub unsafe extern "C" fn picky_pem_data_length(this: Option<&pem_t>) -> c_int {
    let this = none_check!(this, -1);
    err_check!(
        c_int::try_from(this.inner.data().len()).context("invalid data length"),
        -1
    )
}

/// Copy raw data contained in the PEM object.
///
/// Returns the number of bytes written, or `-1` if there was an error.
#[no_mangle]
pub unsafe extern "C" fn picky_pem_data(this: Option<&pem_t>, data: *mut u8, data_sz: c_int) -> c_int {
    let this = none_check!(this, -1);
    let buffer = ptr_to_buffer!(mut @u8 data, data_sz, -1);
    err_check!(copy_slice_to_c(this.inner.data(), buffer), -1)
}

/// Get the length of the pem label in bytes when encoded as UTF-8, including the trailing null.
///
/// Returns the number of required bytes, or `-1` if there was an error.
#[no_mangle]
pub unsafe extern "C" fn picky_pem_label_length(this: Option<&pem_t>) -> c_int {
    let this = none_check!(this, -1);
    err_check!(
        c_int::try_from(this.inner.label().len() + 1).context("invalid label length"),
        -1
    )
}

/// Copy the label associated to the data contained in the PEM object.
///
/// Returns the number of bytes written, or `-1` if there was an error.
#[no_mangle]
pub unsafe extern "C" fn picky_pem_label(this: Option<&pem_t>, label: *mut c_char, label_sz: c_int) -> c_int {
    let this = none_check!(this, -1);
    let buffer = ptr_to_buffer!(mut @c_char label, label_sz, -1);
    err_check!(copy_str_to_c(this.inner.label(), buffer), -1)
}

/// Compute the length of the PEM representation, including the trailing null.
///
/// Returns the number of required bytes, or `-1` if there was an error.
#[no_mangle]
pub unsafe extern "C" fn picky_pem_compute_repr_length(this: Option<&pem_t>) -> c_int {
    let this = none_check!(this, -1);
    let repr = this.inner.to_string();
    err_check!(c_int::try_from(repr.len() + 1).context("invalid repr length"), -1)
}

/// Encodes PEM object to the PEM string representation.
///
/// Returns the number of bytes written, or `-1` if there was an error.
#[no_mangle]
pub unsafe extern "C" fn picky_pem_to_repr(this: Option<&pem_t>, repr: *mut c_char, repr_sz: c_int) -> c_int {
    let this = none_check!(this, -1);
    let buffer = ptr_to_buffer!(mut @c_char repr, repr_sz, -1);
    err_check!(copy_str_to_c(this.inner.to_string(), buffer), -1)
}

/// Frees memory for this PEM object.
#[no_mangle]
pub extern "C" fn picky_pem_drop(_: Option<Box<pem_t>>) {}

/// Returns a cloned version of this PEM object.
#[no_mangle]
pub extern "C" fn picky_pem_clone(src: Option<&pem_t>) -> Option<Box<pem_t>> {
    src.map(|src| Box::new(Clone::clone(src)))
}
