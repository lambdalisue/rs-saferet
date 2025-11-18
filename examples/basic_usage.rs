use saferet::{SecretBytes, SecretString};

fn main() {
    // SecretString example
    let api_key = SecretString::new("sk_live_abc123");
    println!("API Key (debug): {:?}", api_key);
    println!("API Key (display): {}", api_key);
    println!("API Key (exposed): {}", api_key.expose());

    // SecretBytes example
    let crypto_key = SecretBytes::new(vec![0x01, 0x02, 0x03, 0x04]);
    println!("\nCrypto Key (debug): {:?}", crypto_key);
    println!("Crypto Key (display): {}", crypto_key);
    println!("Crypto Key (exposed): {:?}", crypto_key.expose());

    // Equality comparison
    let key1 = SecretString::new("secret");
    let key2 = SecretString::new("secret");
    println!("\nEquality test: {}", key1 == key2);
}
