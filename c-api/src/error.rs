#[diplomat::bridge]
pub mod ffi {
    use diplomat_runtime::DiplomatWriteable;
    use std::fmt::Write as _;

    /// Stringified Picky error.
    #[diplomat::opaque]
    pub struct PickyError(pub String);

    impl PickyError {
        /// Returns the error as a string.
        pub fn to_display(&self, writeable: &mut DiplomatWriteable) {
            let _ = write!(writeable, "{}", self.0);
            writeable.flush();
        }

        /// Prints the error string.
        pub fn print(&self) {
            println!("{}", self.0);
        }
    }
}
