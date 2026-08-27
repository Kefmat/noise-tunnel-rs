//! Protokollrammeverk for meldingsinnkapsling, handshake-flyt og transport.

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::crypto::KEY_LEN;

/// Protokollversjon og "prologue"-streng for å binde sesjonsforhandlingen.
pub const PROTOCOL_NAME: &[u8] = b"Noise_NK_25519_ChaChaPoly_SHA256_v1";

/// Maksimal rammestørrelse (64 KB for å unngå minne-DoS angrep).
pub const MAX_FRAME_SIZE: usize = 65536;

/// Meldings-typer i protokollen
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MessageType {
    HandshakeInit = 0x01,
    HandshakeResp = 0x02,
    DataPayload = 0x03,
    Heartbeat = 0x04,
    Close = 0x05,
}

impl TryFrom<u8> for MessageType {
    type Error = anyhow::Error;

    fn try_from(val: u8) -> Result<Self> {
        match val {
            0x01 => Ok(MessageType::HandshakeInit),
            0x02 => Ok(MessageType::HandshakeResp),
            0x03 => Ok(MessageType::DataPayload),
            0x04 => Ok(MessageType::Heartbeat),
            0x05 => Ok(MessageType::Close),
            other => Err(anyhow!("Ukjent meldingstype mottatt over wire: 0x{:02x}", other)),
        }
    }
}

/// Strukturert pakkeformat over ledningen (Length-Prefixed Wire Frame):
/// [4 bytes: Lengde (u32-BE)] [1 byte: MessageType] [8 bytes: Nonce (u64-BE)] [N bytes: Kryptert Payload + 16b MAC]
pub struct WireFrame {
    pub msg_type: MessageType,
    pub nonce: u64,
    pub payload: Vec<u8>,
}

impl WireFrame {
    pub fn new(msg_type: MessageType, nonce: u64, payload: Vec<u8>) -> Self {
        Self {
            msg_type,
            nonce,
            payload,
        }
    }

    /// Serialiserer rammen til binære bytes for overføring over TCP.
    pub fn serialize(&self) -> Vec<u8> {
        let payload_len = self.payload.len();
        let total_frame_len = 1 + 8 + payload_len; // Type (1) + Nonce (8) + Payload
        let mut buffer = Vec::with_capacity(4 + total_frame_len);

        buffer.extend_from_slice(&(total_frame_len as u32).to_be_bytes());
        buffer.push(self.msg_type as u8);
        buffer.extend_from_slice(&self.nonce.to_be_bytes());
        buffer.extend_from_slice(&self.payload);
        buffer
    }

    /// Skriver rammen asynkront til en TCP-stream.
    pub async fn write_to<W: AsyncWriteExt + Unpin>(&self, stream: &mut W) -> Result<()> {
        let bytes = self.serialize();
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        Ok(())
    }

    /// Leser en komplett ramme asynkront fra en TCP-stream med beskyttelse mot buffer-overflow.
    pub async fn read_from<R: AsyncReadExt + Unpin>(stream: &mut R) -> Result<Self> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let frame_len = u32::from_be_bytes(len_buf) as usize;

        if frame_len < 9 {
            return Err(anyhow!("Mottok for kort wire-ramme: {} bytes", frame_len));
        }
        if frame_len > MAX_FRAME_SIZE {
            return Err(anyhow!(
                "Mottok overdimensjonert pakke ({}), avviser for å forhindre DoS",
                frame_len
            ));
        }

        let mut raw_data = vec![0u8; frame_len];
        stream.read_exact(&mut raw_data).await?;

        let msg_type = MessageType::try_from(raw_data[0])?;
        let nonce = u64::from_be_bytes(raw_data[1..9].try_into()?);
        let payload = raw_data[9..].to_vec();

        Ok(WireFrame {
            msg_type,
            nonce,
            payload,
        })
    }
}

/// Anti-replay filter for å forhindre replay-angrep med glidevindu / historikk.
#[derive(Default)]
pub struct ReplayFilter {
    seen_nonces: HashSet<u64>,
    highest_nonce: u64,
}

impl ReplayFilter {
    pub fn new() -> Self {
        Self {
            seen_nonces: HashSet::new(),
            highest_nonce: 0,
        }
    }

    /// Validerer om en nonce er gyldig og aldri har vært sett før.
    pub fn validate_and_record(&mut self, nonce: u64) -> Result<()> {
        if self.seen_nonces.contains(&nonce) {
            return Err(anyhow!(
                "REPLAY DETECTED! Nonce {} har allerede blitt prosessert!",
                nonce
            ));
        }

        if nonce > self.highest_nonce {
            self.highest_nonce = nonce;
        }

        self.seen_nonces.insert(nonce);

        // Rydd opp gamle nonces om settet blir for stort (behold de siste 10 000)
        if self.seen_nonces.len() > 10000 {
            let cutoff = self.highest_nonce.saturating_sub(5000);
            self.seen_nonces.retain(|&n| n >= cutoff);
        }

        Ok(())
    }
}

/// Hjelpefunksjon for å generere handshake-hash (transcript hash) for integrert sesjonsbinding.
pub fn hash_handshake_state(
    prologue: &[u8],
    client_ephemeral: &[u8; KEY_LEN],
    server_public: &[u8; KEY_LEN],
    server_ephemeral: Option<&[u8; KEY_LEN]>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prologue);
    hasher.update(client_ephemeral);
    hasher.update(server_public);
    if let Some(se) = server_ephemeral {
        hasher.update(se);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_wireframe_serialization_roundtrip() {
        let frame = WireFrame::new(MessageType::DataPayload, 42, b"Hemmelig Payload".to_vec());
        let serialized = frame.serialize();

        let mut cursor = Cursor::new(serialized);
        let parsed = WireFrame::read_from(&mut cursor).await.unwrap();

        assert_eq!(parsed.msg_type, MessageType::DataPayload);
        assert_eq!(parsed.nonce, 42);
        assert_eq!(parsed.payload, b"Hemmelig Payload");
    }

    #[test]
    fn test_replay_filter_blocks_duplicated_nonce() {
        let mut filter = ReplayFilter::new();
        assert!(filter.validate_and_record(1).is_ok());
        assert!(filter.validate_and_record(2).is_ok());

        // Gjenta nonce 1 -> Skal avvises som replay angrep
        let replay_result = filter.validate_and_record(1);
        assert!(replay_result.is_err(), "Replay angrep må detekteres og avvises!");
    }
}
