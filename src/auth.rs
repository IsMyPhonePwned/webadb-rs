use crate::protocol::AdbError;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs8::DecodePrivateKey,
    signature::{SignatureEncoding, Signer},
    RsaPrivateKey, RsaPublicKey,
};
use rsa::pkcs1v15::SigningKey;
use sha1::Sha1;
use base64::{engine::general_purpose, Engine as _};

/// ADB key pair for authentication
pub struct AdbKeyPair {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl AdbKeyPair {
    /// Generate a new 2048-bit RSA key pair
    pub fn generate() -> Result<Self, AdbError> {
        use rsa::rand_core::OsRng;
        
        let mut rng = OsRng;
        let bits = 2048;
        
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| AdbError::AuthenticationFailed(format!("Failed to generate key: {}", e)))?;
        
        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Load from PEM-encoded private key string
    pub fn from_pem(pem: &str) -> Result<Self, AdbError> {
        // Try PKCS#1 first
        let private_key = if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(pem) {
            key
        } else {
            // Try PKCS#8
            RsaPrivateKey::from_pkcs8_pem(pem)
                .map_err(|e| AdbError::AuthenticationFailed(format!("Failed to parse PEM: {}", e)))?
        };

        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Sign a token (challenge from device)
    pub fn sign_token(&self, token: &[u8]) -> Result<Vec<u8>, AdbError> {
        let signing_key = SigningKey::<Sha1>::new(self.private_key.clone());
        
        let signature = signing_key.sign(token);
        Ok(signature.to_bytes().as_ref().to_vec())
    }

    /// Get public key in ADB format
    /// Format: base64(DER-encoded public key) + " " + name + "\x00"
    pub fn get_public_key(&self, name: &str) -> Result<Vec<u8>, AdbError> {
        // Encode public key in PKCS#1 DER format
        let der = self.public_key.to_pkcs1_der()
            .map_err(|e| AdbError::AuthenticationFailed(format!("Failed to encode public key: {}", e)))?;
        
        // Base64 encode the DER bytes
        let encoded = general_purpose::STANDARD.encode(der.as_bytes());
        
        // Format: "base64_key name\x00"
        // This is the format Android ADB expects
        let mut result = encoded.into_bytes();
        result.push(b' ');
        result.extend_from_slice(name.as_bytes());
        result.push(0); // Null terminator

        Ok(result)
    }

    /// Get private key as PEM
    pub fn private_key_pem(&self) -> Result<String, AdbError> {
        let pem = self.private_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| AdbError::AuthenticationFailed(format!("Failed to encode private key: {}", e)))?;
        Ok(pem.to_string())
    }

    /// Get public key as PEM
    pub fn public_key_pem(&self) -> Result<String, AdbError> {
        let pem = self.public_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| AdbError::AuthenticationFailed(format!("Failed to encode public key: {}", e)))?;
        Ok(pem)
    }
}

/// Helper to store and retrieve keys from browser storage
#[cfg(target_arch = "wasm32")]
pub mod storage {
    use super::*;
    use wasm_bindgen::prelude::*;

    const STORAGE_KEY: &str = "adb_private_key";

    /// Save private key to localStorage
    pub fn save_key(keypair: &AdbKeyPair) -> Result<(), AdbError> {
        let pem = keypair.private_key_pem()?;
        
        let window = web_sys::window()
            .ok_or_else(|| AdbError::AuthenticationFailed("No window object".to_string()))?;
        
        let storage = window.local_storage()
            .map_err(|_| AdbError::AuthenticationFailed("Failed to access localStorage".to_string()))?
            .ok_or_else(|| AdbError::AuthenticationFailed("localStorage not available".to_string()))?;

        storage.set_item(STORAGE_KEY, &pem)
            .map_err(|_| AdbError::AuthenticationFailed("Failed to save key".to_string()))?;

        Ok(())
    }

    /// Load private key from localStorage
    pub fn load_key() -> Result<Option<AdbKeyPair>, AdbError> {
        let window = web_sys::window()
            .ok_or_else(|| AdbError::AuthenticationFailed("No window object".to_string()))?;
        
        let storage = window.local_storage()
            .map_err(|_| AdbError::AuthenticationFailed("Failed to access localStorage".to_string()))?
            .ok_or_else(|| AdbError::AuthenticationFailed("localStorage not available".to_string()))?;

        let pem = storage.get_item(STORAGE_KEY)
            .map_err(|_| AdbError::AuthenticationFailed("Failed to load key".to_string()))?;

        match pem {
            Some(pem) => Ok(Some(AdbKeyPair::from_pem(&pem)?)),
            None => Ok(None),
        }
    }

    /// Remove key from localStorage
    pub fn remove_key() -> Result<(), AdbError> {
        let window = web_sys::window()
            .ok_or_else(|| AdbError::AuthenticationFailed("No window object".to_string()))?;
        
        let storage = window.local_storage()
            .map_err(|_| AdbError::AuthenticationFailed("Failed to access localStorage".to_string()))?
            .ok_or_else(|| AdbError::AuthenticationFailed("localStorage not available".to_string()))?;

        storage.remove_item(STORAGE_KEY)
            .map_err(|_| AdbError::AuthenticationFailed("Failed to remove key".to_string()))?;

        Ok(())
    }
}