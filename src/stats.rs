//! Statistikk- og metrikksporing for Noise-Tunnel sesjoner.

use std::fmt;
use std::time::{Duration, Instant};

/// Struktur for sanntidsmåling av dataflyt og rammestatistikk i en sesjon.
#[derive(Debug, Clone)]
pub struct SessionMetrics {
    bytes_sent: u64,
    bytes_received: u64,
    frames_sent: u64,
    frames_received: u64,
    started_at: Instant,
    last_activity: Instant,
}

impl Default for SessionMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionMetrics {
    /// Oppretter en ny metrikk-teller med starttidspunkt satt til nå.
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            frames_sent: 0,
            frames_received: 0,
            started_at: now,
            last_activity: now,
        }
    }

    /// Registrerer en utgående ramme og oppdaterer sendte bytes.
    pub fn record_tx(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
        self.frames_sent += 1;
        self.last_activity = Instant::now();
    }

    /// Registrerer en innkommende ramme og oppdaterer mottatte bytes.
    pub fn record_rx(&mut self, bytes: usize) {
        self.bytes_received += bytes as u64;
        self.frames_received += 1;
        self.last_activity = Instant::now();
    }

    /// Returnerer totalt antall bytes sendt.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Returnerer totalt antall bytes mottatt.
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Returnerer summen av alle bytes sendt og mottatt.
    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }

    /// Returnerer antall utgående rammer.
    pub fn frames_sent(&self) -> u64 {
        self.frames_sent
    }

    /// Returnerer antall innkommende rammer.
    pub fn frames_received(&self) -> u64 {
        self.frames_received
    }

    /// Returnerer totalt antall rammer prosessert i sesjonen.
    pub fn total_frames(&self) -> u64 {
        self.frames_sent + self.frames_received
    }

    /// Returnerer tidsrommet siden sesjonen startet.
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Returnerer tidsrommet siden forrige registrerte aktivitet.
    pub fn idle_duration(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Tilbakestiller alle tellere og setter starttidspunkt til nåværende tidspunkt.
    pub fn reset(&mut self) {
        let now = Instant::now();
        self.bytes_sent = 0;
        self.bytes_received = 0;
        self.frames_sent = 0;
        self.frames_received = 0;
        self.started_at = now;
        self.last_activity = now;
    }
}

impl fmt::Display for SessionMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SessionMetrics(TX: {} frames ({} B), RX: {} frames ({} B), Total: {} B, Elapsed: {:.2?})",
            self.frames_sent,
            self.bytes_sent,
            self.frames_received,
            self.bytes_received,
            self.total_bytes(),
            self.elapsed()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_metrics_recording_and_reset() {
        let mut metrics = SessionMetrics::new();
        assert_eq!(metrics.total_bytes(), 0);
        assert_eq!(metrics.total_frames(), 0);

        metrics.record_tx(100);
        metrics.record_tx(250);
        assert_eq!(metrics.bytes_sent(), 350);
        assert_eq!(metrics.frames_sent(), 2);

        metrics.record_rx(500);
        assert_eq!(metrics.bytes_received(), 500);
        assert_eq!(metrics.frames_received(), 1);
        assert_eq!(metrics.total_bytes(), 850);
        assert_eq!(metrics.total_frames(), 3);

        let display_str = format!("{}", metrics);
        assert!(display_str.contains("TX: 2 frames (350 B)"));
        assert!(display_str.contains("RX: 1 frames (500 B)"));
        assert!(display_str.contains("Total: 850 B"));

        metrics.reset();
        assert_eq!(metrics.total_bytes(), 0);
        assert_eq!(metrics.total_frames(), 0);
        assert_eq!(metrics.bytes_sent(), 0);
        assert_eq!(metrics.bytes_received(), 0);
    }
}
