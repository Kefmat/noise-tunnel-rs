//! Noise-Tunnel-RS: Sikker E2EE Sesjonstunnel med Noise Protocol i Rust.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod client;
mod crypto;
mod protocol;
mod server;
mod verify;

use client::TunnelClient;
use crypto::{KeyPair, KEY_LEN};
use server::TunnelServer;

#[derive(Parser)]
#[command(
    name = "noise-tunnel-rs",
    author = "Kevinmat <kevin_mata98@hotmail.com>",
    version = "0.1.0",
    about = "Ende-til-ende-kryptert (E2EE) asynkron nettverkstunnel i Rust",
    long_about = "En minnesikker, asynkron og autentisert sesjonstunnel basert pa X25519, HKDF-SHA256 og ChaCha20-Poly1305 (Noise NK)."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generer et nytt kryptografisk sikkert X25519 nokkelpar
    Keygen,

    /// Start den sikre tunnel-serveren
    Server {
        /// Adresse og port serveren skal binde til (f.eks. 127.0.0.1:8080)
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        bind: SocketAddr,

        /// Serverens private nokkel i hex-format (genereres automatisk hvis ikke oppgitt)
        #[arg(short, long)]
        private_key: Option<String>,
    },

    /// Koble til server som klient og send en kryptert melding
    Client {
        /// Serverens adresse og port (f.eks. 127.0.0.1:8080)
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        connect: SocketAddr,

        /// Serverens offentlige nokkel i hex-format (kreves for autentisert handshake)
        #[arg(short, long)]
        server_pubkey: String,

        /// Melding som skal krypteres og sendes over tunnelen (brukes ved enkeltmelding)
        #[arg(short, long, default_value = "Hei fra sikker Rust-klient!")]
        message: String,

        /// Start interaktiv live sesjon (REPL / strøm over kryptert tunnel)
        #[arg(short, long)]
        interactive: bool,
    },

    /// Kjor automatisk sikkerhets- og sarbarhetsverifikasjon
    Verify,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialiser logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "noise_tunnel_rs=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen => {
            let keypair = KeyPair::generate();
            println!("\nGenerert nytt X25519 nokkelpar:");
            println!("--------------------------------------------------");
            println!(
                "Privat Nokkel (Hold HEMMELIG): {}",
                hex::encode(keypair.private_key)
            );
            println!(
                "Offentlig Nokkel (Deles fritt): {}",
                hex::encode(keypair.public_key)
            );
            println!("--------------------------------------------------\n");
        }

        Commands::Server { bind, private_key } => {
            let keypair = match private_key {
                Some(hex_str) => {
                    let bytes = hex::decode(hex_str.trim())
                        .context("Kunne ikke dekode privat nokkel fra hex")?;
                    if bytes.len() != KEY_LEN {
                        return Err(anyhow!(
                            "Privat nokkel ma vaere noyaktig {} bytes ({} hex-tegn)",
                            KEY_LEN,
                            KEY_LEN * 2
                        ));
                    }
                    let mut arr = [0u8; KEY_LEN];
                    arr.copy_from_slice(&bytes);
                    KeyPair::from_private_bytes(arr)
                }
                None => {
                    let generated = KeyPair::generate();
                    println!("Ingen privatnokkel oppgitt. Genererte nytt server-nokkelpar:");
                    println!("Privat nokkel: {}", hex::encode(generated.private_key));
                    println!("Offentlig nokkel: {}", hex::encode(generated.public_key));
                    generated
                }
            };

            let server = TunnelServer::new(keypair, bind);
            server.run().await?;
        }

        Commands::Client {
            connect,
            server_pubkey,
            message,
            interactive,
        } => {
            let pubkey_bytes = hex::decode(server_pubkey.trim())
                .context("Kunne ikke dekode server public key fra hex")?;
            if pubkey_bytes.len() != KEY_LEN {
                return Err(anyhow!(
                    "Server public key ma vaere noyaktig {} bytes ({} hex-tegn)",
                    KEY_LEN,
                    KEY_LEN * 2
                ));
            }
            let mut server_pubkey_arr = [0u8; KEY_LEN];
            server_pubkey_arr.copy_from_slice(&pubkey_bytes);

            let client = TunnelClient::new(server_pubkey_arr, connect);

            if interactive {
                client.start_interactive_session().await?;
            } else {
                let response = client.send_secure_message(&message).await?;
                println!("\nMelding sendt og bekreftet kryptert mottatt:");
                println!("Svar: {}\n", response);
            }
        }

        Commands::Verify => {
            verify::run_security_verification().await?;
        }
    }

    Ok(())
}
