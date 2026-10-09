use std::{fmt, ops::Deref};

use crate::{Error, Mac, MacContext, Protection, Zeroizing};

macro_rules! length_debug {
    ($name:ident) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("len", &self.0.len())
                    .finish()
            }
        }
    };
}

/// Variable-length output, wiped on drop; diagnostics expose only its length.
/// See CONTRACT.md section 2.
#[derive(Clone)]
pub struct OutputBytes(Zeroizing<Vec<u8>>);

impl OutputBytes {
    /// Wraps zeroizing storage unchanged.
    /// See CONTRACT.md section 2.
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
    /// Returns the zeroizing storage.
    /// See CONTRACT.md section 2.
    pub fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}
impl Deref for OutputBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}
impl AsRef<[u8]> for OutputBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
length_debug!(OutputBytes);

/// X25519 scalar, wiped on drop; diagnostics expose only its length.
/// See CONTRACT.md sections 2 and 6.13.
#[derive(Clone)]
pub struct X25519Scalar(Zeroizing<[u8; 32]>);
impl X25519Scalar {
    /// Wraps zeroizing storage unchanged, without clamping.
    /// See CONTRACT.md section 2.
    pub fn new(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
    /// Returns the zeroizing storage.
    /// See CONTRACT.md section 2.
    pub fn into_inner(self) -> Zeroizing<[u8; 32]> {
        self.0
    }
}
impl Deref for X25519Scalar {
    type Target = [u8; 32];
    fn deref(&self) -> &[u8; 32] {
        &self.0
    }
}
impl AsRef<[u8]> for X25519Scalar {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}
length_debug!(X25519Scalar);

/// Opaque zeroizing MAC result from a backend context.
/// See CONTRACT.md section 6.2.
pub struct MacOutput(Zeroizing<Vec<u8>>);
impl MacOutput {
    /// Wraps the full tag unchanged.
    /// See CONTRACT.md section 6.2.
    pub fn new(tag: Zeroizing<Vec<u8>>) -> Self {
        Self(tag)
    }
}
length_debug!(MacOutput);

/// Generated tag, wiped on drop; bytes are available only through zeroizing storage.
/// See CONTRACT.md section 6.2.
#[derive(Clone)]
pub struct MacTag(Zeroizing<Vec<u8>>);
impl MacTag {
    /// Returns the full tag to emit or derive from.
    /// See CONTRACT.md section 6.2.
    pub fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}
length_debug!(MacTag);

/// Zeroizing tag that only verifies a received tag.
/// See CONTRACT.md section 6.2.
#[derive(Clone)]
pub struct MacVerifier(Zeroizing<Vec<u8>>);
impl MacVerifier {
    /// Checks a protocol-fixed prefix length with a best-effort constant-time comparison.
    /// Returns false for zero, excessive or mismatched lengths.
    /// See CONTRACT.md section 6.2.
    pub fn verify(&self, expected: &[u8], len: usize) -> bool {
        if expected.len() != len || len == 0 || len > self.0.len() {
            return false;
        }
        let mut difference = 0u8;
        for (&actual, &expected) in self.0[..len].iter().zip(expected) {
            difference |= actual ^ expected;
        }
        std::hint::black_box(difference) == 0
    }
}
length_debug!(MacVerifier);

/// Streaming MAC generation, using applying protection.
/// See CONTRACT.md section 6.2.
pub struct MacGeneration(Box<dyn MacContext>);
impl MacGeneration {
    /// Starts tag generation on the entry.
    /// See CONTRACT.md section 6.2.
    pub fn start(mac: &dyn Mac, key: &[u8]) -> Result<Self, Error> {
        mac.start(key, Protection::Apply).map(Self)
    }
    /// Adds data to the context.
    /// See CONTRACT.md section 6.2.
    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.0.update(data)
    }
    /// Consumes the context and returns the full tag.
    /// See CONTRACT.md section 6.2.
    pub fn finish(self) -> Result<MacTag, Error> {
        self.0.finish().map(|tag| MacTag(tag.0))
    }
}

/// Streaming MAC verification, using processing protection.
/// See CONTRACT.md section 6.2.
pub struct MacVerification(Box<dyn MacContext>);
impl MacVerification {
    /// Starts tag verification on the entry.
    /// See CONTRACT.md section 6.2.
    pub fn start(mac: &dyn Mac, key: &[u8]) -> Result<Self, Error> {
        mac.start(key, Protection::Process).map(Self)
    }
    /// Adds data to the context.
    /// See CONTRACT.md section 6.2.
    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.0.update(data)
    }
    /// Consumes the context and returns a verifier without byte access.
    /// See CONTRACT.md section 6.2.
    pub fn finish(self) -> Result<MacVerifier, Error> {
        self.0.finish().map(|tag| MacVerifier(tag.0))
    }
}

/// Generated nonce and authenticated ciphertext, both wiped on drop.
/// See CONTRACT.md section 6.7.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct Sealed {
    /// Backend-generated nonce: 12 bytes for AES-GCM.
    /// See CONTRACT.md section 6.7.
    pub nonce: OutputBytes,
    /// Ciphertext followed by the tag.
    /// See CONTRACT.md section 6.7.
    pub ciphertext_and_tag: OutputBytes,
}
impl Sealed {
    /// Packages the nonce and ciphertext with tag.
    /// See CONTRACT.md section 6.7.
    pub fn new(nonce: OutputBytes, ciphertext_and_tag: OutputBytes) -> Self {
        Self {
            nonce,
            ciphertext_and_tag,
        }
    }
}
