//! Safe management of secret bytes
//!
//! Provides [`SecretBytes`] type for securely handling sensitive binary information such as
//! cryptographic keys, hashes, and binary tokens.
//!
//! # Security Features
//!
//! - Automatic memory cleanup on Drop using [`zeroize`]
//! - Masked display in Debug/Display (`***`)
//! - Actual value accessible only through the `expose()` method
//!
//! # Usage Example
//!
//! ```
//! # use saferet::SecretBytes;
//! let key = SecretBytes::new(vec![0x01, 0x02, 0x03, 0x04]);
//!
//! // Value is masked in Debug output
//! println!("{:?}", key);  // Output: SecretBytes(***)
//!
//! // Access the actual value
//! let key_slice = key.expose();
//! ```
//!
//! # Security Notes
//!
//! - Do not include `expose()` values in logs or error messages
//! - Vector reallocation may leave copies at old memory locations
//! - With `constant-time-eq` feature (enabled by default), comparison operations use
//!   constant-time algorithms to prevent timing attacks
//!
//! [`zeroize`]: https://docs.rs/zeroize

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt;
#[cfg(feature = "constant-time-eq")]
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Byte vector containing sensitive information
///
/// Automatically cleaned from memory on Drop, and masked in Debug/Display output.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(not(feature = "constant-time-eq"), derive(PartialEq, Eq))]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Create a new `SecretBytes`
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self(secret.into())
    }

    /// Get a reference to the internal byte slice
    ///
    /// # Security Warning
    ///
    /// Do not output this value to logs or include it in error messages.
    /// Use this method carefully and only when necessary.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(***)")
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "***")
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(s: &[u8]) -> Self {
        Self::new(s.to_vec())
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.expose()
    }
}

impl Default for SecretBytes {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

#[cfg(feature = "constant-time-eq")]
impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

#[cfg(feature = "constant-time-eq")]
impl Eq for SecretBytes {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that Debug trait masks sensitive information
    #[test]
    fn test_secret_bytes_debug() {
        let secret = SecretBytes::new(vec![0x01, 0x02, 0x03]);
        let debug_str = format!("{:?}", secret);
        assert_eq!(debug_str, "SecretBytes(***)");
        assert_eq!(secret.expose(), &[0x01, 0x02, 0x03]);
    }

    /// Verify that Display trait masks sensitive information
    #[test]
    fn test_secret_bytes_display() {
        let secret = SecretBytes::new(vec![0x01, 0x02, 0x03]);
        let display_str = format!("{}", secret);
        assert_eq!(display_str, "***");
    }

    /// Verify that zeroize functionality works correctly
    ///
    /// Since automatic zeroize on Drop cannot be directly tested,
    /// verify the behavior of the explicit zeroize() method
    #[test]
    fn test_secret_bytes_zeroize() {
        let mut secret = SecretBytes::new(vec![0x01, 0x02, 0x03]);

        // Verify the value exists
        assert_eq!(secret.expose(), &[0x01, 0x02, 0x03]);

        // Explicitly zeroize
        secret.zeroize();

        // After zeroize, it becomes an empty vector
        assert_eq!(secret.expose(), &[]);
    }

    /// Verify From trait implementations
    #[test]
    fn test_from_implementations() {
        // Conversion from Vec<u8>
        let from_vec: SecretBytes = vec![0x01, 0x02].into();
        assert_eq!(from_vec.expose(), &[0x01, 0x02]);

        // Conversion from &[u8]
        let from_slice: SecretBytes = [0x03, 0x04].as_ref().into();
        assert_eq!(from_slice.expose(), &[0x03, 0x04]);

        // Direct use of From::from
        let direct_from = SecretBytes::from(vec![0x05, 0x06]);
        assert_eq!(direct_from.expose(), &[0x05, 0x06]);
    }

    /// Verify Default trait implementation
    #[test]
    fn test_default() {
        let default_secret = SecretBytes::default();
        assert_eq!(default_secret.expose(), &[]);
    }

    /// Verify that Clone trait works correctly
    #[test]
    fn test_clone() {
        let original = SecretBytes::new(vec![0x01, 0x02]);
        let cloned = original.clone();

        assert_eq!(original.expose(), cloned.expose());
        assert_eq!(original.expose(), &[0x01, 0x02]);
    }

    /// Verify that PartialEq/Eq traits work correctly
    ///
    /// Note: With `constant-time-eq` feature, uses constant-time comparison to prevent timing attacks
    #[test]
    fn test_equality() {
        let secret1 = SecretBytes::new(vec![0x01, 0x02]);
        let secret2 = SecretBytes::new(vec![0x01, 0x02]);
        let secret3 = SecretBytes::new(vec![0x03, 0x04]);

        assert_eq!(secret1, secret2);
        assert_ne!(secret1, secret3);
    }

    /// Verify AsRef trait implementation
    #[test]
    fn test_as_ref() {
        let secret = SecretBytes::new(vec![0x01, 0x02, 0x03]);
        let slice: &[u8] = secret.as_ref();
        assert_eq!(slice, &[0x01, 0x02, 0x03]);
    }
}
