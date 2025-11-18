//! Safe management of secret strings
//!
//! Provides [`SecretString`] type for securely handling sensitive information such as
//! passwords, API keys, and tokens.
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
//! # use saferet::SecretString;
//! let api_key = SecretString::new("sk_live_abc123");
//!
//! // Value is masked in Debug output
//! println!("{:?}", api_key);  // Output: SecretString(***)
//!
//! // Access the actual value
//! let header = format!("Bearer {}", api_key.expose());
//! ```
//!
//! # Security Notes
//!
//! - Do not include `expose()` values in logs or error messages
//! - String reallocation may leave copies at old memory locations
//! - With `constant-time-eq` feature (enabled by default), comparison operations use
//!   constant-time algorithms to prevent timing attacks
//!
//! [`zeroize`]: https://docs.rs/zeroize

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
#[cfg(feature = "constant-time-eq")]
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// String containing sensitive information
///
/// Automatically cleaned from memory on Drop, and masked in Debug/Display output.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(not(feature = "constant-time-eq"), derive(PartialEq, Eq))]
pub struct SecretString(String);

impl SecretString {
    /// Create a new `SecretString`
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// Get a reference to the internal string
    ///
    /// # Security Warning
    ///
    /// Do not output this value to logs or include it in error messages.
    /// Use this method carefully and only when necessary.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(***)")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "***")
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self.expose()
    }
}

impl Default for SecretString {
    fn default() -> Self {
        Self::new("")
    }
}

impl FromStr for SecretString {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

#[cfg(feature = "constant-time-eq")]
impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

#[cfg(feature = "constant-time-eq")]
impl Eq for SecretString {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that Debug trait masks sensitive information
    #[test]
    fn test_secret_string_debug() {
        let secret = SecretString::new("super-secret");
        let debug_str = format!("{:?}", secret);
        assert_eq!(debug_str, "SecretString(***)");
        assert_eq!(secret.expose(), "super-secret");
    }

    /// Verify that Display trait masks sensitive information
    #[test]
    fn test_secret_string_display() {
        let secret = SecretString::new("super-secret");
        let display_str = format!("{}", secret);
        assert_eq!(display_str, "***");
    }

    /// Verify that zeroize functionality works correctly
    ///
    /// Since automatic zeroize on Drop cannot be directly tested,
    /// verify the behavior of the explicit zeroize() method
    #[test]
    fn test_secret_string_zeroize() {
        let mut secret = SecretString::new("sensitive-data");

        // Verify the value exists
        assert_eq!(secret.expose(), "sensitive-data");

        // Explicitly zeroize
        secret.zeroize();

        // After zeroize, it becomes an empty string
        assert_eq!(secret.expose(), "");
    }

    /// Verify From trait implementations
    #[test]
    fn test_from_implementations() {
        // Conversion from String
        let from_string: SecretString = String::from("from_string").into();
        assert_eq!(from_string.expose(), "from_string");

        // Conversion from &str
        let from_str: SecretString = "from_str".into();
        assert_eq!(from_str.expose(), "from_str");

        // Direct use of From::from
        let direct_from = SecretString::from("direct");
        assert_eq!(direct_from.expose(), "direct");
    }

    /// Verify Default trait implementation
    #[test]
    fn test_default() {
        let default_secret = SecretString::default();
        assert_eq!(default_secret.expose(), "");
    }

    /// Verify that Clone trait works correctly
    #[test]
    fn test_clone() {
        let original = SecretString::new("original");
        let cloned = original.clone();

        assert_eq!(original.expose(), cloned.expose());
        assert_eq!(original.expose(), "original");
    }

    /// Verify that PartialEq/Eq traits work correctly
    ///
    /// Note: With `constant-time-eq` feature, uses constant-time comparison to prevent timing attacks
    #[test]
    fn test_equality() {
        let secret1 = SecretString::new("secret");
        let secret2 = SecretString::new("secret");
        let secret3 = SecretString::new("different");

        assert_eq!(secret1, secret2);
        assert_ne!(secret1, secret3);
    }

    /// Verify FromStr trait implementation
    #[test]
    fn test_from_str() {
        // Using parse() method
        let secret: SecretString = "parsed_secret".parse().unwrap();
        assert_eq!(secret.expose(), "parsed_secret");

        // Direct use of FromStr::from_str
        let secret2 = SecretString::from_str("direct_from_str").unwrap();
        assert_eq!(secret2.expose(), "direct_from_str");
    }
}
