use wasm_bindgen::prelude::*;

define_error!(PemError, picky::pem::PemError);

/// PEM object.
#[wasm_bindgen]
pub struct Pem(pub(crate) picky::pem::Pem<'static>);

#[wasm_bindgen]
impl Pem {
    /// Creates a PEM object with the given label and data.
    pub fn new(label: &str, data: &[u8]) -> Result<Pem, PemError> {
        let data = data.to_owned();
        let pem = picky::pem::Pem::new(label, data);
        Ok(Pem(pem))
    }

    /// Parses a PEM-encoded string representation.
    pub fn parse(input: &str) -> Result<Pem, PemError> {
        let pem = picky::pem::parse_pem(input)?;
        Ok(Pem(pem))
    }

    /// Returns the data contained by this PEM object.
    pub fn data(&self) -> Vec<u8> {
        self.0.data().to_vec()
    }

    /// Returns the label of this PEM object.
    pub fn get_label(&self) -> Result<String, PemError> {
        Ok(self.0.label().to_owned())
    }

    /// Returns the string representation of this PEM object.
    pub fn to_repr(&self) -> Result<String, PemError> {
        Ok(format!("{}", self.0))
    }
}
