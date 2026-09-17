//! Eksempel: Enkel, sikker Noise Tunnel Echo Server.
//!
//! Kjor eksempelet med:
//! `cargo run --example echo_server`

use anyhow::Result;
use noise_tunnel_rs::{KeyPair, TunnelServer};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialiser tracing-logger
    tracing_subscriber::fmt::init();

    // 1. Generer serverens statiske X25519 nøkkelpar
    let server_keypair = KeyPair::generate();
    let bind_addr: SocketAddr = "127.0.0.1:8080".parse()?;

    println!("========================================================");
    println!("  NOISE-TUNNEL-RS EKSEMPEL: STANDALONE ECHO SERVER     ");
    println!("========================================================");
    println!(
        "Server offentlig nokkel (hex): {}",
        server_keypair.public_key_hex()
    );
    println!("Lytter pa adresse            : {}", bind_addr);
    println!("Koble til med:");
    println!(
        "  cargo run -- client --connect {} --server-pubkey {} --interactive",
        bind_addr,
        server_keypair.public_key_hex()
    );
    println!("========================================================\n");

    // 2. Konfigurer og start serveren
    let server = TunnelServer::new(server_keypair, bind_addr)
        .with_prologue_str("Noise_Echo_Demo_v1")
        .with_max_connections(50);

    server.run().await?;

    Ok(())
}
