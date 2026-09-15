//! Noise-Tunnel-RS: Sikker E2EE Sesjonstunnel med Noise Protocol i Rust.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use noise_tunnel_rs::client::TunnelClient;
use noise_tunnel_rs::crypto::KeyPair;
use noise_tunnel_rs::server::TunnelServer;
use noise_tunnel_rs::verify;

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

        /// Valgfri tilpasset protokoll-prologue for sesjonsbinding
        #[arg(long)]
        prologue: Option<String>,

        /// Maksimalt antall samtidige klienttilkoblinger
        #[arg(short = 'm', long)]
        max_connections: Option<usize>,
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
                keypair.private_key_hex()
            );
            println!(
                "Offentlig Nokkel (Deles fritt): {}",
                keypair.public_key_hex()
            );
            println!("--------------------------------------------------\n");
        }

        Commands::Server {
            bind,
            private_key,
            prologue,
            max_connections,
        } => {
            let keypair = match private_key {
                Some(hex_str) => {
                    KeyPair::from_private_hex(&hex_str).context("Kunne ikke laste privat nokkel")?
                }
                None => {
                    let generated = KeyPair::generate();
                    println!("Ingen privatnokkel oppgitt. Genererte nytt server-nokkelpar:");
                    println!("Privat nokkel: {}", generated.private_key_hex());
                    println!("Offentlig nokkel: {}", generated.public_key_hex());
                    generated
                }
            };

            let mut server = TunnelServer::new(keypair, bind);
            if let Some(p) = prologue {
                server = server.with_prologue_str(&p);
            }
            if let Some(max) = max_connections {
                server = server.with_max_connections(max);
            }
            server.run().await?;
        }

        Commands::Client {
            connect,
            server_pubkey,
            message,
            interactive,
        } => {
            let server_pubkey_arr = KeyPair::parse_public_key_hex(&server_pubkey)
                .context("Kunne ikke laste server offentlig nokkel")?;

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
