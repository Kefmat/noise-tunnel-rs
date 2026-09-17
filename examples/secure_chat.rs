//! Eksempel: Sikker kryptert chat-sesjon over Noise Tunnel.
//!
//! Kjor eksempelet med:
//! `cargo run --example secure_chat`

use anyhow::Result;
use noise_tunnel_rs::{KeyPair, TunnelClient, TunnelServer};
use std::time::Duration;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    println!("========================================================");
    println!("  NOISE-TUNNEL-RS EKSEMPEL: SIKKER E2EE CHAT-SESJON    ");
    println!("========================================================\n");

    // 1. Finn en ledig port og opprett servernøkler
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    drop(listener);

    let server_keypair = KeyPair::generate();
    let server_pubkey = server_keypair.public_key;

    // 2. Start serveren i en bakgrunns-task
    let server =
        TunnelServer::new(server_keypair, server_addr).with_prologue_str("NoiseChat_Secure_v1");

    tokio::spawn(async move {
        if let Err(e) = server.run().await {
            eprintln!("Server stoppet med feil: {:?}", e);
        }
    });

    // Gi serveren et kort oyeblikk til a binde lytteren
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 3. Konfigurer klienten med matching prologue og timeout
    let client = TunnelClient::new(server_pubkey, server_addr)
        .with_prologue_str("NoiseChat_Secure_v1")
        .with_timeout(Duration::from_secs(5));

    println!("Kobler til sikker chat-server pa {}...\n", server_addr);

    // 4. Send en serie krypterte meldinger
    let chat_messages = [
        "Hei fra Alice! Er denne kanalen fullstendig kryptert?",
        "Ja, vi bruker ChaCha20-Poly1305 med Perfect Forward Secrecy.",
        "Fantastisk! All data er beskyttet mot avlytting og replay-angrep.",
    ];

    for (i, msg) in chat_messages.iter().enumerate() {
        println!("[Alice -> Server]: \"{}\"", msg);
        let reply = client.send_secure_message(msg).await?;
        println!("[Server -> Alice]: \"{}\"\n", reply);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = i;
    }

    println!("========================================================");
    println!("  Sikker chat-sesjon fullfort uten feil!               ");
    println!("========================================================");

    Ok(())
}
