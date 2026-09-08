//! # Noise-Tunnel-RS
//!
//! En minnesikker, asynkron og autentisert ende-til-ende-kryptert (E2EE)
//! sesjonstunnel i Rust, inspirert av Noise Protocol Framework og moderne
//! TLS 1.3-sikkerhetsstandarder.
//!
//! ## Moduler
//! - [`crypto`]: Krypto-primitiver (X25519 nøkkelutveksling, ChaCha20-Poly1305 AEAD, HKDF nøkkelavledning).
//! - [`protocol`]: Trådramme-formatering, meldingsserialisering og glidevindu for replay-beskyttelse.
//! - [`client`]: Tunnel-klient for asynkrone meldinger og interaktive REPL-sesjoner.
//! - [`server`]: Multi-klient asynkron tunnel-server med uavhengige sesjoner.
//! - [`verify`]: Automatiserte krypto- og sårbarhetsverifikasjoner.

pub mod client;
pub mod crypto;
pub mod protocol;
pub mod server;
pub mod verify;

pub use client::TunnelClient;
pub use crypto::{KeyPair, SessionKeys};
pub use protocol::{MessageType, ReplayFilter, WireFrame};
pub use server::TunnelServer;
