//! Sikker Noise-Tunnel TCP Server som håndterer krypterte sesjoner.

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::crypto::{
    derive_session_keys, diffie_hellman, CipherState, EphemeralKeyPair, KeyPair, KEY_LEN,
};
use crate::protocol::{hash_handshake_state, MessageType, ReplayFilter, WireFrame, PROTOCOL_NAME};

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub struct TunnelServer {
    keypair: KeyPair,
    bind_addr: SocketAddr,
    max_connections: Option<usize>,
    active_connections: Arc<AtomicUsize>,
    prologue: Vec<u8>,
}

impl TunnelServer {
    pub fn new(keypair: KeyPair, bind_addr: SocketAddr) -> Self {
        Self {
            keypair,
            bind_addr,
            max_connections: None,
            active_connections: Arc::new(AtomicUsize::new(0)),
            prologue: PROTOCOL_NAME.to_vec(),
        }
    }

    /// Setter maksimalt antall samtidige aktive klientforbindelser (Builder pattern).
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = Some(max);
        self
    }

    /// Konfigurerer en tilpasset protokoll-prologue/identifikator for sesjonsbinding.
    pub fn with_prologue(mut self, prologue: &[u8]) -> Self {
        self.prologue = prologue.to_vec();
        self
    }

    /// Konfigurerer en tilpasset protokoll-prologue fra en streng-slice (&str).
    pub fn with_prologue_str(self, prologue: &str) -> Self {
        self.with_prologue(prologue.as_bytes())
    }

    /// Returnerer eventuell konfigurert grense for samtidige forbindelser.
    pub fn max_connections(&self) -> Option<usize> {
        self.max_connections
    }

    /// Returnerer gjeldende protokoll-prologue.
    pub fn prologue(&self) -> &[u8] {
        &self.prologue
    }

    /// Returnerer antall aktive klientforbindelser i øyeblikket.
    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Returnerer serverens lytteadresse.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Returnerer referanse til serverens offentlige nøkkel.
    pub fn public_key(&self) -> &[u8; KEY_LEN] {
        &self.keypair.public_key
    }

    /// Returnerer serverens offentlige nøkkel i hex-format.
    pub fn public_key_hex(&self) -> String {
        self.keypair.public_key_hex()
    }

    /// Starter server-løkken og lytter etter innkommende forbindelser.
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        info!("Sikker Noise-Tunnel Server lytter pa {}", self.bind_addr);
        info!(
            "Server Public Key (hex): {}",
            hex::encode(self.keypair.public_key)
        );

        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    let active = self.active_connections.load(Ordering::Relaxed);
                    if let Some(max) = self.max_connections {
                        if active >= max {
                            warn!(
                                "Maks antall samtidige forbindelser ({}) nådd! Avviser {}",
                                max, peer_addr
                            );
                            drop(socket);
                            continue;
                        }
                    }

                    info!("Ny klient tilkoblet fra: {}", peer_addr);
                    let server_keys = self.keypair.clone();
                    let counter = Arc::clone(&self.active_connections);
                    let prologue = self.prologue.clone();
                    counter.fetch_add(1, Ordering::Relaxed);

                    tokio::spawn(async move {
                        let res =
                            Self::handle_client_with_prologue(socket, server_keys, peer_addr, &prologue)
                                .await;
                        counter.fetch_sub(1, Ordering::Relaxed);
                        if let Err(e) = res {
                            warn!("Feil eller sesjonsavbrudd for {}: {:?}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Feil ved mottak av tilkobling: {:?}", e);
                }
            }
        }
    }

    /// Utfører Noise-handshake med standard protokoll-prologue.
    pub async fn handle_client(
        stream: TcpStream,
        server_keys: KeyPair,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        Self::handle_client_with_prologue(stream, server_keys, peer_addr, PROTOCOL_NAME).await
    }

    /// Utfører Noise-handshake og oppretter en kryptert toveis tunnel for klienten med gitt prologue.
    pub async fn handle_client_with_prologue(
        mut stream: TcpStream,
        server_keys: KeyPair,
        peer_addr: SocketAddr,
        prologue: &[u8],
    ) -> Result<()> {
        // 1. Motta HandshakeInit fra klient
        let init_frame = WireFrame::read_from(&mut stream).await?;
        if init_frame.msg_type != MessageType::HandshakeInit {
            return Err(anyhow!(
                "Forventet HandshakeInit, mottok {:?}",
                init_frame.msg_type
            ));
        }

        if init_frame.payload.len() < KEY_LEN + 16 {
            return Err(anyhow!("Ugyldig HandshakeInit payload-størrelse"));
        }

        let mut client_ephemeral = [0u8; KEY_LEN];
        client_ephemeral.copy_from_slice(&init_frame.payload[..KEY_LEN]);
        let init_ciphertext = &init_frame.payload[KEY_LEN..];

        // 2. Beregn statisk Diffie-Hellman: DH(e_c, s_s)
        let dh_static = diffie_hellman(&server_keys.private_key, &client_ephemeral);
        let h1 = hash_handshake_state(
            prologue,
            &client_ephemeral,
            &server_keys.public_key,
            None,
        );

        // Verifiser init MAC
        let (k_init_c, _) = derive_session_keys(&dh_static, &h1)?;
        let mut init_cipher = CipherState::new(k_init_c);
        init_cipher.decrypt(init_ciphertext, &h1, 0)?;

        // 3. Generer Server Ephemeral Key e_s og fullfør DH(e_c, e_s)
        let server_ephemeral = EphemeralKeyPair::generate();
        let server_ephem_pub = server_ephemeral.public_key;
        let dh_ephem = server_ephemeral.diffie_hellman(&client_ephemeral);

        // 4. Slå sammen hemmeligheter og avled permanente transport-nøkler
        let mut combined_secret = Vec::with_capacity(KEY_LEN * 2);
        combined_secret.extend_from_slice(&dh_static);
        combined_secret.extend_from_slice(&dh_ephem);

        let h2 = hash_handshake_state(
            prologue,
            &client_ephemeral,
            &server_keys.public_key,
            Some(&server_ephem_pub),
        );

        let (client_write_key, server_write_key) = derive_session_keys(&combined_secret, &h2)?;

        // 5. Send HandshakeResp tilbake til klient
        let (_, k_resp_s) = derive_session_keys(&dh_ephem, &h2)?;
        let mut resp_cipher = CipherState::new(k_resp_s);
        let resp_ciphertext = resp_cipher.encrypt(b"HANDSHAKE_COMPLETE_ACK", &h2)?;

        let mut resp_payload = Vec::with_capacity(KEY_LEN + resp_ciphertext.len());
        resp_payload.extend_from_slice(&server_ephem_pub);
        resp_payload.extend_from_slice(&resp_ciphertext);

        let resp_frame = WireFrame::new(MessageType::HandshakeResp, 0, resp_payload);
        resp_frame.write_to(&mut stream).await?;

        info!("E2EE Handshake vellykket for {}", peer_addr);

        // 6. Transport State
        let mut rx_cipher = CipherState::new(client_write_key);
        let mut tx_cipher = CipherState::new(server_write_key);
        let mut replay_filter = ReplayFilter::new();

        // 7. Behandle krypterte meldinger fra klienten
        loop {
            let frame = match WireFrame::read_from(&mut stream).await {
                Ok(f) => f,
                Err(_) => {
                    info!("Klient {} koblet fra.", peer_addr);
                    break;
                }
            };

            match frame.msg_type {
                MessageType::DataPayload => {
                    replay_filter.validate_and_record(frame.nonce)?;
                    let plaintext =
                        rx_cipher.decrypt(&frame.payload, b"tunnel-data", frame.nonce)?;
                    let msg_str = String::from_utf8_lossy(&plaintext);
                    info!("[Kryptert fra {}]: {}", peer_addr, msg_str);

                    // Send et kryptert ekko-svar tilbake
                    let reply_msg = format!("Server mottok: {}", msg_str);
                    let reply_nonce = tx_cipher.current_nonce();
                    let encrypted_reply =
                        tx_cipher.encrypt(reply_msg.as_bytes(), b"tunnel-data")?;

                    let reply_frame =
                        WireFrame::new(MessageType::DataPayload, reply_nonce, encrypted_reply);
                    reply_frame.write_to(&mut stream).await?;
                }
                MessageType::Heartbeat => {
                    replay_filter.validate_and_record(frame.nonce)?;
                    let _ = rx_cipher.decrypt(&frame.payload, b"heartbeat", frame.nonce)?;
                    let pong_nonce = tx_cipher.current_nonce();
                    let pong = tx_cipher.encrypt(b"PONG", b"heartbeat")?;
                    let pong_frame = WireFrame::heartbeat(pong_nonce, pong);
                    pong_frame.write_to(&mut stream).await?;
                }
                MessageType::Close => {
                    info!("Klient {} sendte Close-signal.", peer_addr);
                    break;
                }
                _ => {
                    warn!("Uventet meldingstype mottatt under transport");
                }
            }
        }

        Ok(())
    }
}
