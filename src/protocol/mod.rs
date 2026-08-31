//! Protokollrammeverk for meldingsinnkapsling, handshake-flyt og transport.

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::crypto::KEY_LEN;

/// Protokollversjon og "prologue"-streng for å binde sesjonsforhandlingen.
pub const PROTOCOL_NAME: &[u8] = b"Noise_NK_25519_ChaChaPoly_SHA256_v1";

/// Maksimal rammestørrelse (64 KB for å unngå minne-DoS angrep).
pub const MAX_FRAME_SIZE: usize = 65536;

/// Standard glidevindu-størrelse for anti-replay (128 pakker).
pub const REPLAY_WINDOW_SIZE: u64 = 128;

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

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::HandshakeInit => write!(f, "HandshakeInit"),
            MessageType::HandshakeResp => write!(f, "HandshakeResp"),
            MessageType::DataPayload => write!(f, "DataPayload"),
            MessageType::Heartbeat => write!(f, "Heartbeat"),
            MessageType::Close => write!(f, "Close"),
        }
    }
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
            other => Err(anyhow!(
                "Ukjent meldingstype mottatt over wire: 0x{:02x}",
                other
            )),
        }
    }
}

/// Strukturert pakkeformat over ledningen (Length-Prefixed Wire Frame):
/// [4 bytes: Lengde (u32-BE)] [1 byte: MessageType] [8 bytes: Nonce (u64-BE)] [N bytes: Kryptert Payload + 16b MAC]
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Sjekker om rammen representerer en handshake-pakke.
    pub fn is_handshake(&self) -> bool {
        matches!(
            self.msg_type,
            MessageType::HandshakeInit | MessageType::HandshakeResp
        )
    }

    /// Sjekker om rammen er et heartbeat.
    pub fn is_heartbeat(&self) -> bool {
        self.msg_type == MessageType::Heartbeat
    }

    /// Sjekker om rammen inneholder kryptert datainnhold.
    pub fn is_data(&self) -> bool {
        self.msg_type == MessageType::DataPayload
    }

    /// Sjekker om rammen er en avslutningsmelding.
    pub fn is_close(&self) -> bool {
        self.msg_type == MessageType::Close
    }

    /// Returnerer lengden på rammens nyttelast i bytes.
    pub fn payload_len(&self) -> usize {
        self.payload.len()
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

/// Anti-replay glidevindu (sliding window) med 128-bit bitmap for O(1) tid og minne.
/// Beskytter mot replay-angrep og håndterer out-of-order levering innenfor vinduet.
#[derive(Debug, Clone)]
pub struct ReplayFilter {
    window_size: u64,
    bitmap: u128,
    last_seq: u64,
    initialized: bool,
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayFilter {
    pub fn new() -> Self {
        Self::with_window_size(REPLAY_WINDOW_SIZE)
    }

    pub fn with_window_size(window_size: u64) -> Self {
        let clamped_size = window_size.clamp(1, 128);
        Self {
            window_size: clamped_size,
            bitmap: 0,
            last_seq: 0,
            initialized: false,
        }
    }

    /// Validerer om en nonce er gyldig og aldri har vært sett før.
    pub fn validate_and_record(&mut self, seq: u64) -> Result<()> {
        if !self.initialized {
            self.last_seq = seq;
            self.bitmap = 1;
            self.initialized = true;
            return Ok(());
        }

        if seq > self.last_seq {
            let diff = seq - self.last_seq;
            if diff < self.window_size {
                self.bitmap <<= diff;
                self.bitmap |= 1;
            } else {
                self.bitmap = 1;
            }
            self.last_seq = seq;
            Ok(())
        } else {
            let diff = self.last_seq - seq;
            if diff >= self.window_size {
                return Err(anyhow!(
                    "REPLAY DETECTED! Sekvensnummer {} er for gammelt (utenfor vinduet på {})",
                    seq,
                    self.window_size
                ));
            }

            let bit = 1u128 << diff;
            if (self.bitmap & bit) != 0 {
                return Err(anyhow!(
                    "REPLAY DETECTED! Sekvensnummer {} har allerede blitt prosessert!",
                    seq
                ));
            }

            self.bitmap |= bit;
            Ok(())
        }
    }

    #[allow(dead_code)]
    pub fn highest_seen(&self) -> u64 {
        self.last_seq
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
    fn test_wireframe_helpers_and_display() {
        let data_frame = WireFrame::new(MessageType::DataPayload, 1, vec![1, 2, 3]);
        assert!(data_frame.is_data());
        assert!(!data_frame.is_handshake());
        assert!(!data_frame.is_heartbeat());
        assert!(!data_frame.is_close());
        assert_eq!(data_frame.payload_len(), 3);
        assert_eq!(format!("{}", MessageType::DataPayload), "DataPayload");

        let hs_frame = WireFrame::new(MessageType::HandshakeInit, 0, vec![]);
        assert!(hs_frame.is_handshake());
        assert_eq!(format!("{}", MessageType::HandshakeInit), "HandshakeInit");

        let hb_frame = WireFrame::new(MessageType::Heartbeat, 2, vec![]);
        assert!(hb_frame.is_heartbeat());
        assert_eq!(format!("{}", MessageType::Heartbeat), "Heartbeat");

        let close_frame = WireFrame::new(MessageType::Close, 3, vec![]);
        assert!(close_frame.is_close());
        assert_eq!(format!("{}", MessageType::Close), "Close");
    }

    #[test]
    fn test_replay_filter_blocks_duplicated_nonce() {
        let mut filter = ReplayFilter::new();
        assert!(filter.validate_and_record(1).is_ok());
        assert!(filter.validate_and_record(2).is_ok());

        // Gjenta nonce 1 -> Skal avvises som replay angrep
        let replay_result = filter.validate_and_record(1);
        assert!(
            replay_result.is_err(),
            "Replay angrep må detekteres og avvises!"
        );
    }

    #[test]
    fn test_replay_filter_sliding_window_out_of_order() {
        let mut filter = ReplayFilter::new();
        assert!(filter.validate_and_record(10).is_ok());
        assert!(filter.validate_and_record(15).is_ok());
        assert!(filter.validate_and_record(12).is_ok()); // gyldig out-of-order innenfor vindu
        assert!(filter.validate_and_record(12).is_err()); // duplikat avvist
        assert!(filter.validate_and_record(15).is_err()); // duplikat avvist
    }

    #[test]
    fn test_replay_filter_old_packet_outside_window() {
        let mut filter = ReplayFilter::with_window_size(64);
        assert!(filter.validate_and_record(100).is_ok());
        assert_eq!(filter.highest_seen(), 100);
        assert!(filter.validate_and_record(200).is_ok()); // Hopper frem, skyver vindu til [137..200]
        assert_eq!(filter.highest_seen(), 200);
        assert!(filter.validate_and_record(100).is_err()); // 100 er nå utenfor vindu
        assert!(filter.validate_and_record(150).is_ok()); // 150 er innenfor [137..200]
        assert!(filter.validate_and_record(150).is_err()); // Duplikat
    }

    #[test]
    fn test_invalid_message_type_rejection() {
        assert!(MessageType::try_from(0x00).is_err());
        assert!(MessageType::try_from(0x99).is_err());
        assert!(MessageType::try_from(0xFF).is_err());
    }

    #[tokio::test]
    async fn test_oversized_frame_rejection() {
        let mut raw = Vec::new();
        // Frame length > MAX_FRAME_SIZE (65536)
        let too_large = (MAX_FRAME_SIZE + 10) as u32;
        raw.extend_from_slice(&too_large.to_be_bytes());
        raw.extend_from_slice(&[0u8; 16]);

        let mut cursor = Cursor::new(raw);
        let res = WireFrame::read_from(&mut cursor).await;
        assert!(res.is_err(), "Overdimensjonert ramme må avvises!");
    }

    #[test]
    fn test_transcript_hash_consistency() {
        let prologue = PROTOCOL_NAME;
        let c_e = [1u8; 32];
        let s_p = [2u8; 32];
        let s_e = [3u8; 32];

        let hash1 = hash_handshake_state(prologue, &c_e, &s_p, Some(&s_e));
        let hash2 = hash_handshake_state(prologue, &c_e, &s_p, Some(&s_e));
        let hash_no_se = hash_handshake_state(prologue, &c_e, &s_p, None);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash_no_se);
    }
}
