#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use diplomat_runtime::DiplomatWriteable;
    use std::fmt::Write as _;
    use std::io::Write as _;

    ///  PEM object.
    #[diplomat::opaque]
    pub struct Pem(pub picky::pem::Pem<'static>);

    impl Pem {
        /// Creates a PEM object with the given label and data.
        pub fn new(label: &str, data: &[u8]) -> Result<Box<Pem>, Box<PickyError>> {
            let data = data.to_owned();
            let pem = picky::pem::Pem::new(label, data);
            Ok(Box::new(Pem(pem)))
        }

        /// Loads a PEM from the filesystem.
        pub fn load_from_file(path: &str) -> Result<Box<Pem>, Box<PickyError>> {
            let contents = std::fs::read_to_string(path)?;
            Self::parse(&contents)
        }

        /// Saves this PEM object to the filesystem.
        pub fn save_to_file(&self, path: &str) -> Result<(), Box<PickyError>> {
            let mut file = std::fs::File::create(path).map(std::io::BufWriter::new)?;
            write!(file, "{}", self.0)?;
            Ok(())
        }

        /// Parses a PEM-encoded string representation.
        pub fn parse(input: &str) -> Result<Box<Pem>, Box<PickyError>> {
            let pem = picky::pem::parse_pem(input)?;
            Ok(Box::new(Pem(pem)))
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
        pub fn get_label(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            write!(writeable, "{}", self.0.label())?;
            writeable.flush();
            Ok(())
        }

        /// Returns the string representation of this PEM object.
        pub fn to_repr(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            write!(writeable, "{}", self.0)?;
            writeable.flush();
            Ok(())
        }
    }
}

/// Retuns data contained in this Pem object.
///
/// # Safety
///
/// Returned data should not be modified.
#[no_mangle]
pub unsafe extern "C" fn Pem_peek_data(pem: Option<&ffi::Pem>, len: *mut usize) -> *const u8 {
    if let Some(pem) = pem {
        let data = pem.0.data();
        *len = data.len();
        data.as_ptr()
    } else {
        core::ptr::null()
    }
}
