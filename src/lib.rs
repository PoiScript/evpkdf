//! Rust implementation of OpenSSL [EVP_bytesToKey] function.
//!
//! `evpkdf` derives key from the given password and salt.
//!
//! Notice that this approach is **too weak** for modern standard
//! now. Newer applications should choice a more modern algorithm
//! like [bcrypt], [pbkdf2] or [scrypt].
//!
//! [EVP_bytesToKey]: https://www.openssl.org/docs/man1.0.2/man3/EVP_BytesToKey.html
//! [bcrypt]: https://crates.io/crates/bcrypt
//! [pbkdf2]: https://crates.io/crates/pbkdf2
//! [scrypt]: https://crates.io/crates/scrypt
//!
//! # Basic Usage
//!
//! ```rust
//! use evpkdf::evpkdf;
//! use hex_literal::hex;
//! use md5::Md5;   // from md-5 crate
//! use sha1::Sha1; // from sha-1 crate
//!
//! let mut output = [];
//!
//! evpkdf::<Md5>(b"password", b"saltsalt", 1000, &mut output);
//!
//! assert_eq!(output, []);
//!
//! let mut output = [0; 128 / 8];
//!
//! evpkdf::<Md5>(b"password", b"saltsalt", 1000, &mut output);
//!
//! assert_eq!(output, hex!("8006de5d2a5d15f9bbdb8f40196d5af1"));
//!
//! let mut output = [0; 128 / 8];
//!
//! evpkdf::<Sha1>(b"password", b"saltsalt", 1000, &mut output);
//!
//! assert_eq!(output, hex!("f8833429b112582447bc66f433497f75"));
//! ```
//!
//! # Compatible with crypto-js
//!
//! Below sinppet generates the same result as
//! `CryptoJS.kdf.OpenSSL.execute('password', 256 / 32, 128 / 32, 'saltsalt')`.
//!
//! ```rust
//! use evpkdf::evpkdf;
//! use hex_literal::hex;
//! use md5::Md5;   // from md-5 crate
//!
//! const KEY_SIZE: usize = 256;
//! const IV_SIZE: usize = 128;
//!
//! let mut output = [0; (KEY_SIZE + IV_SIZE) / 8];
//!
//! evpkdf::<Md5>(b"password", b"saltsalt", 1, &mut output);
//!
//! let (key, iv) = output.split_at(KEY_SIZE / 8);
//!
//! assert_eq!(
//!     key,
//!     hex!("fdbdf3419fff98bdb0241390f62a9db35f4aba29d77566377997314ebfc709f2")
//! );
//!
//! assert_eq!(
//!     iv,
//!     hex!("0b5ca7b1081f94b1ac12e3c8ba87d05a")
//! );
//! ```
//!
//! # License
//!
//! MIT
use digest::Digest;

/// Derives key from the given arguments.
///
/// ```rust
/// use evpkdf::evpkdf;
/// use hex_literal::hex;
/// use md5::Md5;   // from md-5 crate
///
/// let mut output = [0; 128 / 8]; // key size, 128 bits
///
/// evpkdf::<Md5>(
///     b"password", // password
///     b"saltsalt", // salt
///     1000,        // iteration count
///     &mut output
/// );
/// ```
pub fn evpkdf<D: Default + Digest>(pass: &[u8], salt: &[u8], count: usize, output: &mut [u8]) {
    let mut hasher = D::default();
    let mut derived_key = Vec::with_capacity(output.len());
    let mut block = Vec::new();

    while derived_key.len() < output.len() {
        if !block.is_empty() {
            hasher.update(block);
        }
        hasher.update(pass);
        hasher.update(salt.as_ref());
        block = hasher.finalize_reset().to_vec();

        // avoid subtract with overflow
        if count > 1 {
            for _ in 0..(count - 1) {
                hasher.update(block);
                block = hasher.finalize_reset().to_vec();
            }
        }

        derived_key.extend_from_slice(&block);
    }

    output.copy_from_slice(&derived_key[0..output.len()]);
}
