//! # Noise-Tunnel-RS
//!
//! En minnesikker, asynkron og autentisert ende-til-ende-kryptert (E2EE)
//! sesjonstunnel i Rust, inspirert av Noise Protocol Framework (`Noise_NK`) og moderne
//! TLS 1.3-sikkerhetsstandarder.
//!
//! ## Funksjonalitet
//! - **X25519 ECDH**: 1-RTT handshake med Perfect Forward Secrecy (PFS).
//! - **ChaCha20-Poly1305 AEAD**: Symmetrisk 256-bit kryptering og autentisering.
//! - **HKDF-SHA256**: Deterministisk splitting av sesjonsnøkler.
//! - **Anti-Replay Glidevindu**: 128-bit bitmap som detekterer og avviser duplikater i O(1) tid.
//! - **Minnesikkerhet**: Automatisk sletting av hemmelige nøkler med `ZeroizeOnDrop`.
//!
//! ## Moduler
//! - [`crypto`]: Krypto-primitiver (X25519 nøkkelutveksling, ChaCha20-Poly1305 AEAD, HKDF nøkkelavledning).
//! - [`protocol`]: Trådramme-formatering, meldingsserialisering og glidevindu for replay-beskyttelse.
//! - [`client`]: Tunnel-klient for asynkrone meldinger og interaktive REPL-sesjoner.
//! - [`server`]: Multi-klient asynkron tunnel-server med uavhengige sesjoner.
//! - [`verify`]: Automatiserte krypto- og sårbarhetsverifikasjoner.
//! - [`error`]: Strukturerte domene-feiltyper ([`TunnelError`]).
//! - [`stats`]: Statistikk og metrikker for aktive sesjoner ([`SessionMetrics`]).
//! - [`bench`]: Krypto- og protokoll-ytelsesbenchmarkinger.

pub mod bench;
pub mod client;
pub mod crypto;
pub mod error;
pub mod protocol;
pub mod server;
pub mod stats;
pub mod verify;

pub use error::{TunnelError, TunnelResult};
pub use stats::SessionMetrics;

pub use bench::run_benchmark_suite;
pub use client::TunnelClient;
pub use crypto::{
    CipherState, EphemeralKeyPair, KeyPair, SessionKeys, KEY_LEN, NONCE_LEN, TAG_LEN,
};
pub use protocol::{
    hash_handshake_state, MessageType, ReplayFilter, WireFrame, MAX_FRAME_SIZE, PROTOCOL_NAME,
    REPLAY_WINDOW_SIZE,
};
pub use server::TunnelServer;
