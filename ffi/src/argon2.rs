#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use diplomat_runtime::DiplomatWriteable;

    #[diplomat::opaque]
    pub struct Argon2Params {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        output_len: Option<usize>,
    }

    impl Argon2Params {
        /// Create new parameters.
        pub fn new() -> Box<Self> {
            Box::new(Self {
                m_cost: argon2::Params::DEFAULT_M_COST,
                t_cost: argon2::Params::DEFAULT_T_COST,
                p_cost: argon2::Params::DEFAULT_P_COST,
                output_len: None,
            })
        }

        /// Sets the memory size in 1 KiB blocks. Between 1 and (2^32)-1.
        pub fn set_m_cost(&mut self, value: u32) {
            self.m_cost = value;
        }

        /// Sets the number of iterations. Between 1 and (2^32)-1.
        pub fn set_t_cost(&mut self, value: u32) {
            self.t_cost = value;
        }

        /// Sets the degree of parallelism. Between 1 and 255.
        pub fn set_p_cost(&mut self, value: u32) {
            self.p_cost = value;
        }

        /// Sets the size of the KDF output in bytes. Default 32.
        pub fn set_output_len(&mut self, value: usize) {
            self.output_len = Some(value);
        }
    }

    #[derive(Clone, Copy)]
    pub enum Argon2Algorithm {
        Argon2d,
        Argon2i,
        Argon2id,
    }

    #[diplomat::opaque]
    pub struct Argon2(pub argon2::Argon2<'static>);

    impl Argon2 {
        pub fn new(algorithm: Argon2Algorithm, parameters: &Argon2Params) -> Result<Box<Argon2>, Box<PickyError>> {
            let algorithm = match algorithm {
                Argon2Algorithm::Argon2d => argon2::Algorithm::Argon2d,
                Argon2Algorithm::Argon2i => argon2::Algorithm::Argon2i,
                Argon2Algorithm::Argon2id => argon2::Algorithm::Argon2id,
            };

            let params = argon2::Params::new(
                parameters.m_cost,
                parameters.t_cost,
                parameters.p_cost,
                parameters.output_len,
            )?;

            let argon2 = argon2::Argon2::new(algorithm, argon2::Version::V0x13, params);

            Ok(Box::new(Self(argon2)))
        }

        pub fn hash_password(&self, password: &str, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            use argon2::password_hash::rand_core::OsRng;
            use argon2::password_hash::SaltString;
            use argon2::PasswordHasher as _;
            use std::fmt::Write as _;

            let salt = SaltString::generate(&mut OsRng);

            let password_hash = self.0.hash_password(password.as_bytes(), &salt)?.to_string();

            writeable.write_str(&password_hash)?;
            writeable.flush();

            Ok(())
        }
    }
}
