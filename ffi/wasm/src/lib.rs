#[macro_use]
mod macros;

pub mod jwt;
pub mod key;
pub mod pem;
pub mod putty;
pub mod ssh;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn init_picky() -> Result<(), JsValue> {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    Ok(())
}
