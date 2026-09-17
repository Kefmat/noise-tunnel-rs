//! Eksempel: Domene-isolasjon og sesjonsbinding med tilpasset prologue.
//!
//! Kjor eksempelet med:
//! `cargo run --example custom_prologue`

use anyhow::Result;
use noise_tunnel_rs::{KeyPair, TunnelClient, TunnelServer};
use std::time::Duration;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    println!("========================================================");
    println!("  NOISE-TUNNEL-RS: PROLOGUE DOMENE-SEPARASJON         ");
    println!("========================================================\n");

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    drop(listener);

    let server_keypair = KeyPair::generate();
    let server_pubkey = server_keypair.public_key;

    // Server krever prologue "FinansTjeneste_v2"
    let server_prologue = "FinansTjeneste_v2";
    let server = TunnelServer::new(server_keypair, server_addr).with_prologue_str(server_prologue);

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(80)).await;

    // 1. Klient med matchende prologue lykkes
    println!(
        "[Test 1] Klient med korrekt prologue (\"{}\")...",
        server_prologue
    );
    let valid_client =
        TunnelClient::new(server_pubkey, server_addr).with_prologue_str(server_prologue);

    let reply = valid_client
        .send_secure_message("Autentisert transaksjonsordre")
        .await?;
    println!("  Handshake og melding godkjent: \"{}\"\n", reply);

    // 2. Klient med feil prologue avvises
    let invalid_prologue = "AnnenTjeneste_v1";
    println!(
        "[Test 2] Klient med feil prologue (\"{}\")...",
        invalid_prologue
    );
    let invalid_client =
        TunnelClient::new(server_pubkey, server_addr).with_prologue_str(invalid_prologue);

    let result = invalid_client
        .send_secure_message("Ugyldig kontekstforsok")
        .await;

    match result {
        Ok(_) => panic!("Handshake skulle ha feilet pga feil prologue!"),
        Err(e) => {
            println!(
                "  Handshake avvist som forventet pga transkript-mismatch: {:?}",
                e
            );
        }
    }

    println!("\n========================================================");
    println!("  Domene-isolasjonstest fullfort med suksess!          ");
    println!("========================================================");

    Ok(())
}
