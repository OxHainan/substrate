#![allow(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use codec::{Decode, Encode};

/// Error aes gcm
#[derive(Debug, Encode, Decode)]
pub enum Error {
	/// Bad encrypted
	BadEncrypted,

	/// Bad decrypted
	BadDecrypted,

	/// Bad shared key length
	BadKeyLength,
}

// encrypt
pub fn encrypt(msg: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Error> {
	Aes256Gcm::new_from_slice(&crate::hashing::keccak_256(b"12"))
		.map_err(|_| Error::BadKeyLength)?
		.encrypt(Nonce::from_slice(&crate::keccak_256(nonce)[20..]), msg)
		.map_err(|_| Error::BadEncrypted)
}

// decrypt
pub fn decrypt(msg: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Error> {
	Aes256Gcm::new_from_slice(&crate::hashing::keccak_256(b"12"))
		.map_err(|_| Error::BadKeyLength)?
		.decrypt(Nonce::from_slice(&crate::keccak_256(nonce)[20..]), msg)
		.map_err(|_| Error::BadDecrypted)
}
