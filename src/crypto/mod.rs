//! Kjerne-kryptografiske moduler for nøkkelutveksling, nøkkelavledning og AEAD-kryptering.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Lengde på symmetrisk sesjonsnøkkel (32 bytes = 256 bits).
pub const KEY_LEN: usize = 32;
/// Lengde på ChaCha20-Poly1305 nonce (12 bytes = 96 bits).
pub const NONCE_LEN: usize = 12;
/// Lengde på Poly1305 autentiseringstag (16 bytes = 128 bits).
#[allow(dead_code)]
pub const TAG_LEN: usize = 16;

/// Statisk hemmelig nøkkelpar for X25519.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    pub private_key: [u8; KEY_LEN],
    #[zeroize(skip)]
    pub public_key: [u8; KEY_LEN],
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::generate()
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &hex::encode(self.public_key))
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl KeyPair {
    /// Genererer et nytt kryptografisk sikkert X25519 nøkkelpar fra systemets CSPRNG.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self {
            private_key: secret.to_bytes(),
            public_key: *public.as_bytes(),
        }
    }

    /// Oppretter et nøkkelpar fra en eksisterende privat nøkkel (32 bytes).
    pub fn from_private_bytes(bytes: [u8; KEY_LEN]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = X25519PublicKey::from(&secret);
        Self {
            private_key: bytes,
            public_key: *public.as_bytes(),
        }
    }

    /// Oppretter et nøkkelpar fra en hex-enkodet privat nøkkel.
    pub fn from_private_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| anyhow!("Ugyldig hex-enkoding for privat nøkkel: {:?}", e))?;
        if bytes.len() != KEY_LEN {
            return Err(anyhow!(
                "Privat nøkkel må være nøyaktig {} bytes ({} hex-tegn), mottok {}",
                KEY_LEN,
                KEY_LEN * 2,
                bytes.len()
            ));
        }
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_private_bytes(arr))
    }

    /// Parser en offentlig nøkkel fra hex-format til en 32-byte array.
    pub fn parse_public_key_hex(hex_str: &str) -> Result<[u8; KEY_LEN]> {
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| anyhow!("Ugyldig hex-enkoding for offentlig nøkkel: {:?}", e))?;
        if bytes.len() != KEY_LEN {
            return Err(anyhow!(
                "Offentlig nøkkel må være nøyaktig {} bytes ({} hex-tegn), mottok {}",
                KEY_LEN,
                KEY_LEN * 2,
                bytes.len()
            ));
        }
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Returnerer den offentlige nøkkelen som hex-streng.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    /// Returnerer den private nøkkelen som hex-streng.
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key)
    }
}

/// Tilstandsfull AEAD-krypteringskontekst (CipherState) med monotoon nonce-håndtering.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CipherState {
    key: [u8; KEY_LEN],
    #[zeroize(skip)]
    nonce: u64,
}

impl CipherState {
    /// Initialiserer CipherState med en avledet 32-byte symmetrisk nøkkel.
    pub fn new(key: [u8; KEY_LEN]) -> Self {
        Self { key, nonce: 0 }
    }

    /// Nåværende nonce-teller.
    pub fn current_nonce(&self) -> u64 {
        self.nonce
    }

    /// Lager en 12-byte nonce fra en 64-bit monotont økende teller (Little-Endian med null-padding).
    fn build_nonce(counter: u64) -> [u8; NONCE_LEN] {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[..8].copy_from_slice(&counter.to_le_bytes());
        nonce_bytes
    }

    /// Krypterer en melding med ChaCha20-Poly1305 AEAD og inkrementerer nonce automatisk.
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        let nonce_arr = Self::build_nonce(self.nonce);
        let cipher_nonce = Nonce::from_slice(&nonce_arr);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));

        let payload = Payload {
            msg: plaintext,
            aad: associated_data,
        };

        let ciphertext = cipher
            .encrypt(cipher_nonce, payload)
            .map_err(|e| anyhow!("Krypteringsfeil (AEAD): {:?}", e))?;

        // Monotont økende nonce for å unngå nonce-gjenbruk (kritisk for ChaCha20)
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or_else(|| anyhow!("Nonce overflow! Sesjonen må reforhandles."))?;

        Ok(ciphertext)
    }

    /// Dekrypterer en melding og verifiserer autentiseringstagen (Poly1305).
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        associated_data: &[u8],
        expected_nonce: u64,
    ) -> Result<Vec<u8>> {
        if expected_nonce != self.nonce {
            return Err(anyhow!(
                "Ugyldig nonce rekkefølge! Forventet {}, mottok {}",
                self.nonce,
                expected_nonce
            ));
        }

        let nonce_arr = Self::build_nonce(expected_nonce);
        let cipher_nonce = Nonce::from_slice(&nonce_arr);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));

        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };

        let plaintext = cipher.decrypt(cipher_nonce, payload).map_err(|_| {
            anyhow!("AEAD-dekryptering feilet: Ugyldig MAC-tag eller manipulert pakke!")
        })?;

        self.nonce += 1;
        Ok(plaintext)
    }
}

/// Nøkkelavledningsfunksjon (HKDF-SHA256) som splitter felles hemmelighet til to sesjonsnøkler.
/// Returnerer `(client_to_server_key, server_to_client_key)`.
pub fn derive_session_keys(
    shared_secret: &[u8],
    handshake_hash: &[u8],
) -> Result<([u8; KEY_LEN], [u8; KEY_LEN])> {
    let hk = Hkdf::<Sha256>::new(Some(handshake_hash), shared_secret);

    let mut client_write_key = [0u8; KEY_LEN];
    let mut server_write_key = [0u8; KEY_LEN];

    hk.expand(b"noise-tunnel-client-write-key-v1", &mut client_write_key)
        .map_err(|e| anyhow!("HKDF expand for client key feilet: {:?}", e))?;

    hk.expand(b"noise-tunnel-server-write-key-v1", &mut server_write_key)
        .map_err(|e| anyhow!("HKDF expand for server key feilet: {:?}", e))?;

    Ok((client_write_key, server_write_key))
}

/// Utfører X25519 Diffie-Hellman beregning med efemer privatnøkkel og motpartens offentlige nøkkel.
pub fn diffie_hellman(secret_bytes: &[u8; KEY_LEN], public_bytes: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let secret = StaticSecret::from(*secret_bytes);
    let public = X25519PublicKey::from(*public_bytes);
    let shared = secret.diffie_hellman(&public);
    *shared.as_bytes()
}

/// Efemer nøkkel-struktur for handshake (genereres ferskt for hver sesjon).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralKeyPair {
    secret: [u8; KEY_LEN],
    #[zeroize(skip)]
    pub public_key: [u8; KEY_LEN],
}

impl EphemeralKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self {
            secret: secret.to_bytes(),
            public_key: *public.as_bytes(),
        }
    }

    pub fn diffie_hellman(&self, peer_public: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
        diffie_hellman(&self.secret, peer_public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_key_exchange_agreement() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let alice_shared = diffie_hellman(&alice.private_key, &bob.public_key);
        let bob_shared = diffie_hellman(&bob.private_key, &alice.public_key);

        assert_eq!(
            alice_shared, bob_shared,
            "Diffie-Hellman hemmeligheter må være identiske!"
        );
    }

    #[test]
    fn test_aead_encryption_and_decryption() {
        let key = [0x42u8; KEY_LEN];
        let mut sender_cipher = CipherState::new(key);
        let mut receiver_cipher = CipherState::new(key);

        let secret_msg = b"Topphemmelig melding over tunnelen!";
        let aad = b"header-metadata-v1";

        let ciphertext = sender_cipher.encrypt(secret_msg, aad).unwrap();
        assert_ne!(ciphertext, secret_msg);

        let decrypted = receiver_cipher.decrypt(&ciphertext, aad, 0).unwrap();
        assert_eq!(decrypted, secret_msg);
    }

    #[test]
    fn test_aead_tamper_detection() {
        let key = [0x55u8; KEY_LEN];
        let mut sender = CipherState::new(key);
        let mut receiver = CipherState::new(key);

        let mut ciphertext = sender.encrypt(b"Valid Data", b"aad").unwrap();
        // Manipuler en enkelt bit i chifferteksten
        ciphertext[0] ^= 0x01;

        let result = receiver.decrypt(&ciphertext, b"aad", 0);
        assert!(
            result.is_err(),
            "Manipulert chiffertekst må avvises av AEAD MAC-sjekk!"
        );
    }

    #[test]
    fn test_hkdf_session_key_derivation_deterministic() {
        let secret = [0x11u8; KEY_LEN];
        let hash = [0x22u8; 32];

        let (c1, s1) = derive_session_keys(&secret, &hash).unwrap();
        let (c2, s2) = derive_session_keys(&secret, &hash).unwrap();

        assert_eq!(c1, c2);
        assert_eq!(s1, s2);
        assert_ne!(c1, s1, "Klient- og server-nøkler må være unike");
    }

    #[test]
    fn test_keypair_hex_roundtrip_and_parsing() {
        let keypair = KeyPair::generate();
        let priv_hex = keypair.private_key_hex();
        let pub_hex = keypair.public_key_hex();

        assert_eq!(priv_hex.len(), KEY_LEN * 2);
        assert_eq!(pub_hex.len(), KEY_LEN * 2);

        let restored = KeyPair::from_private_hex(&priv_hex).unwrap();
        assert_eq!(restored.public_key, keypair.public_key);
        assert_eq!(restored.private_key, keypair.private_key);

        let parsed_pub = KeyPair::parse_public_key_hex(&pub_hex).unwrap();
        assert_eq!(parsed_pub, keypair.public_key);

        // Ugyldig hex / feil lengde
        assert!(KeyPair::from_private_hex("invalid-hex").is_err());
        assert!(KeyPair::from_private_hex("aabbcc").is_err());
        assert!(KeyPair::parse_public_key_hex("1234").is_err());
    }

    #[test]
    fn test_keypair_debug_redacts_private_key() {
        let keypair = KeyPair::generate();
        let debug_str = format!("{:?}", keypair);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(&hex::encode(keypair.private_key)));
        assert!(debug_str.contains(&keypair.public_key_hex()));
    }

    #[test]
    fn test_keypair_default_generates_valid_keypair() {
        let keypair = KeyPair::default();
        assert_ne!(keypair.private_key, [0u8; KEY_LEN]);
        assert_ne!(keypair.public_key, [0u8; KEY_LEN]);
    }
}
