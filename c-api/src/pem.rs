#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use diplomat_runtime::{DiplomatResult, DiplomatWriteable};
    use std::fmt::Write as _;
    use std::io::Write as _;

    /// Picky PEM object.
    #[diplomat::opaque]
    pub struct PickyPem(pub picky::pem::Pem<'static>);

    impl PickyPem {
        /// Creates a PEM object with the given label and data.
        pub fn new(label: &str, data: &[u8]) -> DiplomatResult<Box<PickyPem>, Box<PickyError>> {
            let data = data.to_owned();
            let pem = picky::pem::Pem::new(label, data);
            Ok(Box::new(PickyPem(pem))).into()
        }

        /// Loads a PEM from the filesystem.
        pub fn load_from_file(path: &str) -> DiplomatResult<Box<PickyPem>, Box<PickyError>> {
            let contents = err_check!(std::fs::read_to_string(path));
            Self::parse(&contents)
        }

        /// Saves this PEM object to the filesystem.
        pub fn save_to_file(&self, path: &str) -> DiplomatResult<(), Box<PickyError>> {
            let mut file = std::io::BufWriter::new(err_check!(std::fs::File::create(path)));
            err_check!(write!(file, "{}", self.0));
            Ok(()).into()
        }

        /// Parses a PEM-encoded string representation.
        pub fn parse(input: &str) -> DiplomatResult<Box<PickyPem>, Box<PickyError>> {
            let pem = err_check!(picky::pem::parse_pem(input));
            Ok(Box::new(PickyPem(pem))).into()
        }

        // TODO(diplomat): support for returning buffers
        // /// Returns the data contained by this PEM object.
        // pub fn data(&self) -> Vec<u8> {
        //     self.0.data().to_vec()
        // }

        /// Returns the length of the data contained by this PEM object.
        pub fn get_data_length(&self) -> u64 {
            self.0.data().len() as u64
        }

        /// Returns the label of this PEM object.
        pub fn get_label(&self, writeable: &mut DiplomatWriteable) -> DiplomatResult<(), Box<PickyError>> {
            err_check!(write!(writeable, "{}", self.0.label()));
            writeable.flush();
            Ok(()).into()
        }

        /// Returns the string representation of this PEM object.
        pub fn to_repr(&self, writeable: &mut DiplomatWriteable) -> DiplomatResult<(), Box<PickyError>> {
            err_check!(write!(writeable, "{}", self.0));
            writeable.flush();
            Ok(()).into()
        }
    }
}
