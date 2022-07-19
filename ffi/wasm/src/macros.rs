macro_rules! define_error {
    ($name:ident, $ty:ty) => {
        #[derive(Debug)]
        #[::wasm_bindgen::prelude::wasm_bindgen]
        pub struct $name(pub(crate) $ty);

        #[::wasm_bindgen::prelude::wasm_bindgen]
        impl $name {
            /// Returns the error as a string.
            pub fn to_display(&self) -> String {
                self.0.to_string()
            }

            /// Returns the debug string representation of the error.
            pub fn to_debug(&self) -> String {
                format!("{self:?}")
            }
        }

        impl From<$ty> for $name {
            fn from(e: $ty) -> Self {
                Self(e)
            }
        }
    };
}
