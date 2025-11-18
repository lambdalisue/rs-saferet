# saferet

[![Crates.io Version](https://img.shields.io/crates/v/saferet)](https://crates.io/crates/saferet)
[![docs.rs](https://img.shields.io/docsrs/saferet)](https://docs.rs/saferet/)

**Secure types for handling sensitive data in Rust**

Provides `SecretString` and `SecretBytes` for safely managing passwords, API keys, cryptographic keys, and other sensitive information with automatic memory cleanup and protection against accidental exposure.

## Key Security Features

- 🔒 **Automatic memory cleanup**: Uses [`zeroize`](https://docs.rs/zeroize) to clear sensitive data from memory on Drop
- 🎭 **Masked display**: Debug and Display implementations show `***` instead of actual values
- 🔐 **Controlled access**: Actual values accessible only through explicit `expose()` method
- ⏱️ **Timing-attack resistant**: Optional constant-time comparison to prevent timing attacks
- 🪶 **Lightweight**: Minimal dependencies with optional features

## Quick Start

```rust
use saferet::{SecretString, SecretBytes};

// SecretString for text-based secrets
let api_key = SecretString::new("sk_live_abc123");
println!("{:?}", api_key);  // Output: SecretString(***)

// Access the actual value when needed
let header = format!("Bearer {}", api_key.expose());

// SecretBytes for binary secrets
let crypto_key = SecretBytes::new(vec![0x01, 0x02, 0x03, 0x04]);
println!("{:?}", crypto_key);  // Output: SecretBytes(***)

// Constant-time comparison (enabled by default)
let password1 = SecretString::new("secret");
let password2 = SecretString::new("secret");
assert_eq!(password1, password2);  // Uses constant-time comparison
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
saferet = "0.1"
```

### Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `constant-time-eq` | Timing-attack resistant comparison using [`subtle`](https://docs.rs/subtle) | ✅ Enabled |
| `serde` | Serialize/Deserialize support | ✅ Enabled |

**Minimal configuration** (zeroize only):
```toml
[dependencies]
saferet = { version = "0.1", default-features = false }
```

**Custom features**:
```toml
[dependencies]
# Only constant-time comparison, no serde
saferet = { version = "0.1", default-features = false, features = ["constant-time-eq"] }

# Only serde support, no constant-time comparison
saferet = { version = "0.1", default-features = false, features = ["serde"] }
```

## Types

### SecretString

For text-based sensitive data like passwords, API keys, and authentication tokens.

```rust
use saferet::SecretString;

let password = SecretString::new("my-secret-password");

// Masked in logs and error messages
println!("{}", password);      // Output: ***
println!("{:?}", password);    // Output: SecretString(***)

// Explicit access when needed
if password.expose() == "my-secret-password" {
    // Use password.expose() carefully
}

// Works with various string types
let from_string: SecretString = String::from("key").into();
let from_str: SecretString = "key".into();
let parsed: SecretString = "key".parse().unwrap();
```

### SecretBytes

For binary sensitive data like cryptographic keys, hashes, and binary tokens.

```rust
use saferet::SecretBytes;

let key = SecretBytes::new(vec![0x01, 0x02, 0x03, 0x04]);

// Masked in logs and error messages
println!("{}", key);      // Output: ***
println!("{:?}", key);    // Output: SecretBytes(***)

// Explicit access when needed
let key_slice: &[u8] = key.expose();
// or using AsRef
let key_slice: &[u8] = key.as_ref();

// Works with various byte types
let from_vec: SecretBytes = vec![0x01, 0x02].into();
let from_slice: SecretBytes = [0x03, 0x04].as_ref().into();
```

## Security Guarantees

### ✅ What saferet provides

- **Memory cleanup**: Sensitive data is zeroized when dropped
- **Accidental exposure prevention**: Debug/Display never show actual values
- **Timing-attack resistance**: Comparison operations run in constant time (with `constant-time-eq` feature)
- **Explicit access control**: Values only accessible through `expose()` method

### ⚠️ What saferet does NOT prevent

- **Intentional exposure**: If you call `expose()` and log/print the result, the value will be exposed
- **Memory copies**: String/Vec reallocation may leave copies at old memory locations
- **Swap memory**: OS may swap memory to disk before zeroization
- **Core dumps**: Process crashes may dump memory to disk
- **Side-channel attacks**: Does not protect against advanced attacks like speculative execution

**Best practices**:
- Minimize calls to `expose()`
- Never include `expose()` results in logs, error messages, or debug output
- Use `constant-time-eq` feature for cryptographic comparisons
- Consider platform-specific secure memory allocation for highly sensitive data

## Serde Support

With the `serde` feature (enabled by default), both types support serialization:

```rust
use saferet::SecretString;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Config {
    #[serde(default)]
    api_key: SecretString,
}

// Serialization includes the actual value
// ⚠️ Be careful when serializing to logs or untrusted destinations
let config = Config {
    api_key: SecretString::new("secret-key"),
};
let json = serde_json::to_string(&config).unwrap();
// json contains the actual "secret-key" value
```

**Security note**: Serialization bypasses the masking protection. Only serialize when absolutely necessary and ensure the destination is secure.

## Comparison Behavior

### With `constant-time-eq` feature (default)

Uses constant-time comparison via the `subtle` crate to prevent timing attacks:

```rust
let secret1 = SecretString::new("password");
let secret2 = SecretString::new("password");
let secret3 = SecretString::new("different");

assert_eq!(secret1, secret2);  // Constant-time comparison
assert_ne!(secret1, secret3);  // Constant-time comparison
```

### Without `constant-time-eq` feature

Uses standard `PartialEq` implementation (faster but potentially vulnerable to timing attacks):

```toml
[dependencies]
saferet = { version = "0.1", default-features = false }
```

## Examples

See the [`examples/`](examples/) directory:

```bash
cargo run --example basic_usage
```

## Testing

Run all tests with all feature combinations:

```bash
# All features (default)
cargo test

# No features
cargo test --no-default-features

# Individual features
cargo test --no-default-features --features serde
cargo test --no-default-features --features constant-time-eq
```

## Use Cases

- **API Keys**: Store API keys securely without risking exposure in logs
- **Passwords**: Handle user passwords with automatic cleanup
- **OAuth Tokens**: Manage authentication tokens safely
- **Database Credentials**: Store connection strings and passwords
- **Cryptographic Keys**: Handle encryption keys with timing-attack protection
- **JWT Secrets**: Manage signing keys for JSON Web Tokens

## Comparison with Other Crates

| Crate | Zeroize | Masked Display | Constant-time Eq | Type Safety |
|-------|---------|----------------|------------------|-------------|
| `saferet` | ✅ | ✅ | ✅ (optional) | String + Bytes |
| `secrecy` | ✅ | ✅ | ❌ | Generic |
| `zeroize` | ✅ | ❌ | ❌ | Generic |
| `subtle` | ❌ | ❌ | ✅ | Primitives |

`saferet` combines the best features in an easy-to-use package specifically designed for string and byte secrets.

## License

Licensed under MIT license ([LICENSE](LICENSE) or http://opensource.org/licenses/MIT).

## Contribution

Contributions are welcome! Please feel free to submit a Pull Request.
