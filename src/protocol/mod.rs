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

impl MessageType {
    /// Returnerer den underliggende byte-verdien til meldingstypen.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Sjekker om meldingstypen representerer en handshake-fase.
    pub fn is_handshake(&self) -> bool {
        matches!(
            self,
            MessageType::HandshakeInit | MessageType::HandshakeResp
        )
    }

    /// Sjekker om meldingstypen er kryptert brukerdata.
    pub fn is_data(&self) -> bool {
        *self == MessageType::DataPayload
    }

    /// Sjekker om meldingstypen er et heartbeat / ping-pong signal.
    pub fn is_heartbeat(&self) -> bool {
        *self == MessageType::Heartbeat
    }

    /// Sjekker om meldingstypen er et avslutningssignal (Close).
    pub fn is_close(&self) -> bool {
        *self == MessageType::Close
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

    /// Oppretter en ny HandshakeInit-ramme.
    pub fn handshake_init(nonce: u64, payload: Vec<u8>) -> Self {
        Self::new(MessageType::HandshakeInit, nonce, payload)
    }

    /// Oppretter en ny HandshakeResp-ramme.
    pub fn handshake_resp(nonce: u64, payload: Vec<u8>) -> Self {
        Self::new(MessageType::HandshakeResp, nonce, payload)
    }

    /// Oppretter en ny DataPayload-ramme.
    pub fn data(nonce: u64, payload: Vec<u8>) -> Self {
        Self::new(MessageType::DataPayload, nonce, payload)
    }

    /// Oppretter en ny Heartbeat-ramme.
    pub fn heartbeat(nonce: u64, payload: Vec<u8>) -> Self {
        Self::new(MessageType::Heartbeat, nonce, payload)
    }

    /// Oppretter en ny Close-ramme.
    pub fn close(nonce: u64) -> Self {
        Self::new(MessageType::Close, nonce, Vec::new())
    }

    /// Sjekker om rammen representerer en handshake-pakke.
    pub fn is_handshake(&self) -> bool {
        self.msg_type.is_handshake()
    }

    /// Sjekker om rammen er et heartbeat.
    pub fn is_heartbeat(&self) -> bool {
        self.msg_type.is_heartbeat()
    }

    /// Sjekker om rammen inneholder kryptert datainnhold.
    pub fn is_data(&self) -> bool {
        self.msg_type.is_data()
    }

    /// Sjekker om rammen er en avslutningsmelding.
    pub fn is_close(&self) -> bool {
        self.msg_type.is_close()
    }

    /// Returnerer lengden på rammens nyttelast i bytes.
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// Sjekker om rammens nyttelast er tom.
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    /// Returnerer rammens meldingstype.
    pub fn msg_type(&self) -> MessageType {
        self.msg_type
    }

    /// Returnerer rammens sekvensnummer/nonce.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Returnerer referanse til rammens nyttelast (slice uten allokering).
    pub fn payload_slice(&self) -> &[u8] {
        &self.payload
    }

    /// Returnerer de 9 byte-headerne til rammen ([1 byte type] + [8 bytes nonce]).
    pub fn header_bytes(&self) -> [u8; 9] {
        let mut header = [0u8; 9];
        header[0] = self.msg_type as u8;
        header[1..9].copy_from_slice(&self.nonce.to_be_bytes());
        header
    }

    /// Returnerer en kompakt oppsummering av rammens metadata (type, nonce, payload-størrelse).
    pub fn summary(&self) -> String {
        format!(
            "WireFrame(type={}, nonce={}, payload_len={}B)",
            self.msg_type,
            self.nonce,
            self.payload.len()
        )
    }

    /// Serialiserer rammen direkte inn i en eksisterende byte-buffer uten nye allokeringer.
    pub fn serialize_into(&self, buffer: &mut Vec<u8>) {
        let payload_len = self.payload.len();
        let total_frame_len = 1 + 8 + payload_len; // Type (1) + Nonce (8) + Payload
        buffer.reserve(4 + total_frame_len);

        buffer.extend_from_slice(&(total_frame_len as u32).to_be_bytes());
        buffer.push(self.msg_type as u8);
        buffer.extend_from_slice(&self.nonce.to_be_bytes());
        buffer.extend_from_slice(&self.payload);
    }

    /// Serialiserer rammen til binære bytes for overføring over TCP.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.serialize_into(&mut buffer);
        buffer
    }

    /// Skriver rammen asynkront til en TCP-stream.
    pub async fn write_to<W: AsyncWriteExt + Unpin>(&self, stream: &mut W) -> Result<()> {
        let bytes = self.serialize();
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        Ok(())
    }

    /// Deserialiserer en WireFrame fra en komplett serialisert byte-buffer (inkludert 4-byte lengdeprefiks).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 13 {
            return Err(anyhow!(
                "Mottok for kort buffer for WireFrame: {} bytes (krever minst 13 bytes)",
                bytes.len()
            ));
        }

        let frame_len = u32::from_be_bytes(bytes[0..4].try_into()?) as usize;
        if frame_len != bytes.len() - 4 {
            return Err(anyhow!(
                "Uoverensstemmelse i rammelengde: spesifisert {}, faktisk bufferlengde {}",
                frame_len,
                bytes.len() - 4
            ));
        }

        if frame_len < 9 {
            return Err(anyhow!("Mottok for kort wire-ramme: {} bytes", frame_len));
        }

        if frame_len > MAX_FRAME_SIZE {
            return Err(anyhow!(
                "Mottok overdimensjonert pakke ({}), avviser for å forhindre DoS",
                frame_len
            ));
        }

        let msg_type = MessageType::try_from(bytes[4])?;
        let nonce = u64::from_be_bytes(bytes[5..13].try_into()?);
        let payload = bytes[13..].to_vec();

        Ok(WireFrame {
            msg_type,
            nonce,
            payload,
        })
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

impl TryFrom<&[u8]> for WireFrame {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
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
    total_seen: u64,
    total_accepted: u64,
    total_rejected: u64,
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
            total_seen: 0,
            total_accepted: 0,
            total_rejected: 0,
        }
    }

    /// Validerer om en nonce er gyldig og aldri har vært sett før.
    pub fn validate_and_record(&mut self, seq: u64) -> Result<()> {
        self.total_seen += 1;

        if !self.initialized {
            self.last_seq = seq;
            self.bitmap = 1;
            self.initialized = true;
            self.total_accepted += 1;
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
            self.total_accepted += 1;
            Ok(())
        } else {
            let diff = self.last_seq - seq;
            if diff >= self.window_size {
                self.total_rejected += 1;
                return Err(anyhow!(
                    "REPLAY DETECTED! Sekvensnummer {} er for gammelt (utenfor vinduet på {})",
                    seq,
                    self.window_size
                ));
            }

            let bit = 1u128 << diff;
            if (self.bitmap & bit) != 0 {
                self.total_rejected += 1;
                return Err(anyhow!(
                    "REPLAY DETECTED! Sekvensnummer {} har allerede blitt prosessert!",
                    seq
                ));
            }

            self.bitmap |= bit;
            self.total_accepted += 1;
            Ok(())
        }
    }

    #[allow(dead_code)]
    pub fn highest_seen(&self) -> u64 {
        self.last_seq
    }

    /// Returnerer konfigurert glidevindu-størrelse / kapasitet.
    pub fn window_size(&self) -> u64 {
        self.window_size
    }

    /// Alias for vindusstørrelse.
    pub fn capacity(&self) -> u64 {
        self.window_size
    }

    /// Sjekker om sekvensnummeret allerede er registrert eller utenfor vinduet uten å modifisere tilstanden.
    pub fn has_seen(&self, seq: u64) -> bool {
        if !self.initialized {
            return false;
        }
        if seq > self.last_seq {
            return false;
        }
        let diff = self.last_seq - seq;
        if diff >= self.window_size {
            return true; // Utenfor vindu (for gammelt)
        }
        let bit = 1u128 << diff;
        (self.bitmap & bit) != 0
    }

    /// Sjekker om filteret har mottatt sin første sekvens.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returnerer totalt antall pakker som har blitt validert.
    pub fn total_seen(&self) -> u64 {
        self.total_seen
    }

    /// Returnerer totalt antall godkjente pakker.
    pub fn total_accepted(&self) -> u64 {
        self.total_accepted
    }

    /// Returnerer totalt antall avviste replay- eller utdaterte pakker.
    pub fn total_rejected(&self) -> u64 {
        self.total_rejected
    }

    /// Tilbakestiller filtertilstanden og tellerne til utgangspunktet.
    pub fn reset(&mut self) {
        self.bitmap = 0;
        self.last_seq = 0;
        self.initialized = false;
        self.total_seen = 0;
        self.total_accepted = 0;
        self.total_rejected = 0;
    }
}

impl std::fmt::Display for ReplayFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ReplayFilter(window={}, last_seq={}, accepted={}/{}, rejected={})",
            self.window_size,
            self.last_seq,
            self.total_accepted,
            self.total_seen,
            self.total_rejected
        )
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
        let data_frame = WireFrame::data(1, vec![1, 2, 3]);
        assert!(data_frame.is_data());
        assert!(!data_frame.is_handshake());
        assert!(!data_frame.is_heartbeat());
        assert!(!data_frame.is_close());
        assert_eq!(data_frame.payload_len(), 3);
        assert!(!data_frame.is_empty());
        assert_eq!(format!("{}", MessageType::DataPayload), "DataPayload");

        let hs_frame = WireFrame::handshake_init(0, vec![]);
        assert!(hs_frame.is_handshake());
        assert!(hs_frame.is_empty());
        assert_eq!(format!("{}", MessageType::HandshakeInit), "HandshakeInit");

        let hs_resp_frame = WireFrame::handshake_resp(0, vec![10, 20]);
        assert!(hs_resp_frame.is_handshake());
        assert_eq!(format!("{}", MessageType::HandshakeResp), "HandshakeResp");

        let hb_frame = WireFrame::heartbeat(2, vec![]);
        assert!(hb_frame.is_heartbeat());
        assert!(hb_frame.is_empty());
        assert_eq!(format!("{}", MessageType::Heartbeat), "Heartbeat");

        let close_frame = WireFrame::close(3);
        assert!(close_frame.is_close());
        assert!(close_frame.is_empty());
        assert_eq!(format!("{}", MessageType::Close), "Close");

        let header = data_frame.header_bytes();
        assert_eq!(header[0], MessageType::DataPayload as u8);
        assert_eq!(&header[1..9], &1u64.to_be_bytes());

        let summary = data_frame.summary();
        assert!(summary.contains("DataPayload"));
        assert!(summary.contains("nonce=1"));
        assert!(summary.contains("payload_len=3B"));
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

    #[test]
    fn test_replay_filter_reset_and_helpers() {
        let mut filter = ReplayFilter::with_window_size(64);
        assert_eq!(filter.window_size(), 64);
        assert!(!filter.is_initialized());

        assert!(filter.validate_and_record(42).is_ok());
        assert!(filter.is_initialized());
        assert_eq!(filter.highest_seen(), 42);

        filter.reset();
        assert!(!filter.is_initialized());
        assert_eq!(filter.highest_seen(), 0);

        // Can accept 42 again after reset
        assert!(filter.validate_and_record(42).is_ok());
    }

    #[test]
    fn test_wireframe_from_bytes_roundtrip_and_errors() {
        let frame = WireFrame::data(100, b"Buffer Data".to_vec());
        let serialized = frame.serialize();

        let parsed = WireFrame::from_bytes(&serialized).unwrap();
        assert_eq!(parsed, frame);

        let try_from_parsed = WireFrame::try_from(serialized.as_slice()).unwrap();
        assert_eq!(try_from_parsed, frame);

        // For kort buffer (< 13 bytes)
        assert!(WireFrame::from_bytes(&[0u8; 10]).is_err());

        // Ugyldig rammelengde i header
        let mut corrupted_len = serialized.clone();
        corrupted_len[0..4].copy_from_slice(&500u32.to_be_bytes());
        assert!(WireFrame::from_bytes(&corrupted_len).is_err());

        // Ugyldig meldingstype
        let mut corrupted_type = serialized.clone();
        corrupted_type[4] = 0xFE;
        assert!(WireFrame::from_bytes(&corrupted_type).is_err());
    }

    #[test]
    fn test_replay_filter_metrics() {
        let mut filter = ReplayFilter::new();
        assert_eq!(filter.total_seen(), 0);
        assert_eq!(filter.total_accepted(), 0);
        assert_eq!(filter.total_rejected(), 0);

        assert!(filter.validate_and_record(10).is_ok());
        assert!(filter.validate_and_record(11).is_ok());
        assert_eq!(filter.total_seen(), 2);
        assert_eq!(filter.total_accepted(), 2);
        assert_eq!(filter.total_rejected(), 0);

        // Replay attempt
        assert!(filter.validate_and_record(10).is_err());
        assert_eq!(filter.total_seen(), 3);
        assert_eq!(filter.total_accepted(), 2);
        assert_eq!(filter.total_rejected(), 1);

        filter.reset();
        assert_eq!(filter.total_seen(), 0);
        assert_eq!(filter.total_accepted(), 0);
        assert_eq!(filter.total_rejected(), 0);
    }

    #[test]
    fn test_wireframe_serialize_into_buffer_reuse() {
        let frame1 = WireFrame::data(1, b"first".to_vec());
        let frame2 = WireFrame::data(2, b"second".to_vec());

        let mut buffer = Vec::new();
        frame1.serialize_into(&mut buffer);
        let len1 = buffer.len();

        let parsed1 = WireFrame::from_bytes(&buffer[..len1]).unwrap();
        assert_eq!(parsed1, frame1);

        buffer.clear();
        frame2.serialize_into(&mut buffer);
        let parsed2 = WireFrame::from_bytes(&buffer).unwrap();
        assert_eq!(parsed2, frame2);
    }

    #[test]
    fn test_wireframe_payload_slice_and_replay_filter_display() {
        let payload = b"slice test payload".to_vec();
        let frame = WireFrame::data(42, payload.clone());
        assert_eq!(frame.payload_slice(), payload.as_slice());

        let mut filter = ReplayFilter::with_window_size(64);
        filter.validate_and_record(10).unwrap();
        let display_str = format!("{}", filter);
        assert!(display_str.contains("window=64"));
        assert!(display_str.contains("last_seq=10"));
        assert!(display_str.contains("accepted=1/1"));
        assert!(display_str.contains("rejected=0"));
    }

    #[test]
    fn test_message_type_predicates_and_byte_conversion() {
        let init = MessageType::HandshakeInit;
        assert_eq!(init.as_u8(), 0x01);
        assert!(init.is_handshake());
        assert!(!init.is_data());
        assert!(!init.is_heartbeat());
        assert!(!init.is_close());

        let resp = MessageType::HandshakeResp;
        assert_eq!(resp.as_u8(), 0x02);
        assert!(resp.is_handshake());

        let data = MessageType::DataPayload;
        assert_eq!(data.as_u8(), 0x03);
        assert!(data.is_data());
        assert!(!data.is_handshake());

        let hb = MessageType::Heartbeat;
        assert_eq!(hb.as_u8(), 0x04);
        assert!(hb.is_heartbeat());

        let close = MessageType::Close;
        assert_eq!(close.as_u8(), 0x05);
        assert!(close.is_close());
    }

    #[test]
    fn test_wireframe_accessors_and_replay_filter_has_seen() {
        let frame = WireFrame::data(77, b"payload".to_vec());
        assert_eq!(frame.nonce(), 77);
        assert_eq!(frame.msg_type(), MessageType::DataPayload);

        let mut filter = ReplayFilter::with_window_size(64);
        assert_eq!(filter.capacity(), 64);
        assert!(!filter.has_seen(10));

        filter.validate_and_record(10).unwrap();
        assert!(filter.has_seen(10));
        assert!(!filter.has_seen(11));

        filter.validate_and_record(100).unwrap();
        // 10 er nå utenfor vinduet [37..100]
        assert!(filter.has_seen(10));
    }
}
