//! Sikker Noise-Tunnel TCP Klient for initiere handshake og sende kryptert trafikk.

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::info;

use crate::crypto::{
    derive_session_keys, CipherState, EphemeralKeyPair, KEY_LEN,
};
use crate::protocol::{
    hash_handshake_state, MessageType, WireFrame, PROTOCOL_NAME,
};

pub struct TunnelClient {
    server_pubkey: [u8; KEY_LEN],
    target_addr: SocketAddr,
}

impl TunnelClient {
    pub fn new(server_pubkey: [u8; KEY_LEN], target_addr: SocketAddr) -> Self {
        Self {
            server_pubkey,
            target_addr,
        }
    }

    /// Etablerer TCP-tilkobling, gjennomfører Noise-handshake, og sender en kryptert melding.
    pub async fn send_secure_message(&self, message: &str) -> Result<String> {
        info!("Kobler til server pa {}...", self.target_addr);
        let mut stream = TcpStream::connect(self.target_addr).await?;

        // 1. Generer klientens engangsnokkel (Ephemeral Key e_c)
        let client_ephemeral = EphemeralKeyPair::generate();
        let client_ephem_pub = client_ephemeral.public_key;

        // 2. Beregn statisk DH(e_c, s_s) med serverens kjente offentlige nokkel
        let dh_static = client_ephemeral.diffie_hellman(&self.server_pubkey);
        let h1 = hash_handshake_state(PROTOCOL_NAME, &client_ephem_pub, &self.server_pubkey, None);

        // Krypter HandshakeInit payload
        let (k_init_c, _) = derive_session_keys(&dh_static, &h1)?;
        let mut init_cipher = CipherState::new(k_init_c);
        let init_ciphertext = init_cipher.encrypt(b"HANDSHAKE_INIT_CLIENT", &h1)?;

        let mut init_payload = Vec::with_capacity(KEY_LEN + init_ciphertext.len());
        init_payload.extend_from_slice(&client_ephem_pub);
        init_payload.extend_from_slice(&init_ciphertext);

        let init_frame = WireFrame::new(MessageType::HandshakeInit, 0, init_payload);
        init_frame.write_to(&mut stream).await?;
        info!("Sendte HandshakeInit til server...");

        // 3. Motta HandshakeResp fra server
        let resp_frame = WireFrame::read_from(&mut stream).await?;
        if resp_frame.msg_type != MessageType::HandshakeResp {
            return Err(anyhow!("Forventet HandshakeResp, mottok {:?}", resp_frame.msg_type));
        }

        if resp_frame.payload.len() < KEY_LEN + 16 {
            return Err(anyhow!("Ugyldig HandshakeResp payload-storrelse fra server"));
        }

        let mut server_ephemeral_pub = [0u8; KEY_LEN];
        server_ephemeral_pub.copy_from_slice(&resp_frame.payload[..KEY_LEN]);
        let resp_ciphertext = &resp_frame.payload[KEY_LEN..];

        // 4. Beregn efemer DH(e_c, e_s)
        let dh_ephem = client_ephemeral.diffie_hellman(&server_ephemeral_pub);

        let h2 = hash_handshake_state(
            PROTOCOL_NAME,
            &client_ephem_pub,
            &self.server_pubkey,
            Some(&server_ephemeral_pub),
        );

        // Verifiser servers handshake-respons
        let (_, k_resp_s) = derive_session_keys(&dh_ephem, &h2)?;
        let mut resp_cipher = CipherState::new(k_resp_s);
        let resp_ack = resp_cipher.decrypt(resp_ciphertext, &h2, 0)?;

        if resp_ack != b"HANDSHAKE_COMPLETE_ACK" {
            return Err(anyhow!("Ugyldig bekreftelse fra server under handshake!"));
        }

        // 5. Avled de permanente transport-noklene
        let mut combined_secret = Vec::with_capacity(KEY_LEN * 2);
        combined_secret.extend_from_slice(&dh_static);
        combined_secret.extend_from_slice(&dh_ephem);

        let (client_write_key, server_write_key) = derive_session_keys(&combined_secret, &h2)?;

        info!("E2EE Handshake fullfort! Sikker sesjon opprettet.");

        let mut tx_cipher = CipherState::new(client_write_key);
        let mut rx_cipher = CipherState::new(server_write_key);

        // 6. Send den krypterte datameldingen over tunnelen
        let tx_nonce = tx_cipher.current_nonce();
        let encrypted_data = tx_cipher.encrypt(message.as_bytes(), b"tunnel-data")?;

        let data_frame = WireFrame::new(MessageType::DataPayload, tx_nonce, encrypted_data);
        data_frame.write_to(&mut stream).await?;
        info!("Sendte kryptert melding ({} bytes): \"{}\"", message.len(), message);

        // 7. Motta kryptert svar fra server
        let reply_frame = WireFrame::read_from(&mut stream).await?;
        if reply_frame.msg_type != MessageType::DataPayload {
            return Err(anyhow!("Forventet kryptert svarmelding, mottok {:?}", reply_frame.msg_type));
        }

        let decrypted_reply = rx_cipher.decrypt(&reply_frame.payload, b"tunnel-data", reply_frame.nonce)?;
        let reply_text = String::from_utf8(decrypted_reply)?;
        info!("Dekryptert svar fra server: \"{}\"", reply_text);

        // Send Close frame for ren avslutning
        let close_frame = WireFrame::new(MessageType::Close, tx_cipher.current_nonce(), vec![]);
        let _ = close_frame.write_to(&mut stream).await;

        Ok(reply_text)
    }
}
