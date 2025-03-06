use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305,
};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum CryptoError {
    KeyExchangeError,
    EncryptionError,
    DecryptionError,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::KeyExchangeError => write!(f, "Erreur lors de l'échange de clés"),
            CryptoError::EncryptionError => write!(f, "Erreur lors du chiffrement"),
            CryptoError::DecryptionError => write!(f, "Erreur lors du déchiffrement"),
        }
    }
}

impl Error for CryptoError {}

pub struct KeyPair {
    pub private_key: StaticSecret,
    pub public_key: PublicKey,
}

impl KeyPair {
    pub fn new() -> Self {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    pub fn from_private_key(private_key: StaticSecret) -> Self {
        let public_key = PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }
}

pub fn generate_ephemeral_keypair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn derive_shared_secret(
    my_private_key: &StaticSecret,
    their_public_key: &PublicKey,
) -> [u8; 32] {
    let shared_secret = my_private_key.diffie_hellman(their_public_key);
    blake3::hash(shared_secret.as_bytes()).into()
}

pub fn encrypt_message(
    message: &[u8],
    shared_secret: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(shared_secret.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    
    let ciphertext = cipher
        .encrypt(&nonce, message)
        .map_err(|_| CryptoError::EncryptionError)?;
    
    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

pub fn decrypt_message(
    encrypted_message: &[u8],
    shared_secret: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    if encrypted_message.len() < 24 {
        return Err(CryptoError::DecryptionError);
    }
    
    let nonce = &encrypted_message[..24];
    let ciphertext = &encrypted_message[24..];
    
    let cipher = XChaCha20Poly1305::new(shared_secret.into());
    
    cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| CryptoError::DecryptionError)
} 