//! Feiltyper for Noise-Tunnel-RS.

use thiserror::Error;

/// Domene-spesifikke feil for Noise-Tunnel operasjoner.
#[derive(Error, Debug)]
pub enum TunnelError {
    #[error("Kryptografisk feil: {0}")]
    Crypto(String),

    #[error("Handshake-feil: {0}")]
    Handshake(String),

    #[error("Replay-angrep detektert for sekvensnummer {seq}: {reason}")]
    Replay { seq: u64, reason: String },

    #[error("Protokoll-rammefeil: {0}")]
    Frame(String),

    #[error("Nettverks- og I/O-feil: {0}")]
    Io(#[from] std::io::Error),

    #[error("Operasjon timet ut: {0}")]
    Timeout(String),

    #[error("Maksimal serverkapasitet nådd ({0} forbindelser)")]
    CapacityExceeded(usize),

    #[error("Hex-dekodingsfeil: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Ugyldig UTF-8 data: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("Ugyldig datalengde: forventet {expected} bytes, mottok {actual} bytes")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Generell feil: {0}")]
    Other(String),
}

impl From<anyhow::Error> for TunnelError {
    fn from(err: anyhow::Error) -> Self {
        TunnelError::Other(err.to_string())
    }
}

/// Typealias for Result med TunnelError.
pub type TunnelResult<T> = std::result::Result<T, TunnelError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_formatting() {
        let crypto_err = TunnelError::Crypto("Ugyldig MAC".to_string());
        assert_eq!(crypto_err.to_string(), "Kryptografisk feil: Ugyldig MAC");

        let replay_err = TunnelError::Replay {
            seq: 42,
            reason: "Duplikat".to_string(),
        };
        assert!(replay_err.to_string().contains("sekvensnummer 42"));
        assert!(replay_err.to_string().contains("Duplikat"));

        let len_err = TunnelError::InvalidLength {
            expected: 32,
            actual: 16,
        };
        assert_eq!(
            len_err.to_string(),
            "Ugyldig datalengde: forventet 32 bytes, mottok 16 bytes"
        );

        let cap_err = TunnelError::CapacityExceeded(100);
        assert_eq!(
            cap_err.to_string(),
            "Maksimal serverkapasitet nådd (100 forbindelser)"
        );
    }
}
