# Noise-Tunnel-RS

![CI](https://github.com/Kefmat/noise-tunnel-rs/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)

> En minnesikker, asynkron og autentisert ende-til-ende-kryptert (E2EE) nettverkstunnel i **Rust**, inspirert av **Noise Protocol Framework** og moderne TLS 1.3-sikkerhetsprinsipper.

---

## Kryptografisk Arkitektur & Sikkerhetsdesign

Noise-Tunnel-RS implementerer en forenklet, robust versjon av **Noise_NK**-protokollen over TCP:

| Komponent | Algoritme / Primitive | Formål |
| :--- | :--- | :--- |
| **Nøkkelutveksling (KEX)** | **X25519** (Curve25519 ECDH) | Etablering av delt hemmelighet med *Perfect Forward Secrecy (PFS)* |
| **Nøkkelavledning (KDF)** | **HKDF-SHA256** (RFC 5869) | Avledning av to uavhengige sesjonsnøkler (*Client $\rightarrow$ Server* og *Server $\rightarrow$ Client*) |
| **Autentisert Kryptering (AEAD)** | **ChaCha20-Poly1305** (RFC 8439) | Konfidensialitet og integritetsbeskyttelse mot tukling (16-byte Poly1305 MAC) |
| **Minnesikkerhet** | `zeroize` | Automatisk overskriving av hemmelige nøkler og sesjonsmateriale fra RAM ved drop |
| **Replay Attack-beskyttelse** | 128-bit Bitmap Sliding Window | O(1) tid og minne for å detektere og blokkere duplikate eller forsinkede pakker |

---

## Protokollflyt (Handshake & Transport)

```text
 Client (Initiator)                                Server (Responder)
   [Ephemeral e_c]                                   [Static S_s, Ephemeral e_s]
          │                                                   │
          │ ─── 1. Handshake Init: e_c.pub, Auth Tag ───────> │  (ECDH: e_c + S_s)
          │                                                   │
          │ <── 2. Handshake Resp: e_s.pub, Auth Tag ──────── │  (ECDH: e_c + e_s)
          │                                                   │
   [Split Keys derived via HKDF]                     [Split Keys derived via HKDF]
   (Tx: Key_CS, Rx: Key_SC)                          (Tx: Key_SC, Rx: Key_CS)
          │                                                   │
          │ ════════════ 3. Encrypted Data Tunnel ═══════════ │
          │ ─── Encrypted Frame (Nonce N_1, Tag_1) ─────────> │
          │ <── Encrypted Frame (Nonce N_2, Tag_2) ────────── │
```

### Trådramme-format (Binary Wire Frame)

Alle meldinger over TCP innkapsles i en length-prefixed ramme:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Frame Length (4 bytes, BE)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| MsgType (1 B) |           Nonce / Sequence (8 bytes, BE)      |
+-+-+-+-+-+-+-+-+                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Encrypted Payload + Poly1305 MAC               |
|                           (N bytes)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Felt | Størrelse | Beskrivelse |
| :--- | :--- | :--- |
| **Length** | 4 bytes (u32-BE) | Total rammelengde ekskludert lengdefeltet (maks 64 KB DoS-grense) |
| **MessageType** | 1 byte (u8) | `0x01`: HandshakeInit, `0x02`: HandshakeResp, `0x03`: Data, `0x04`: Heartbeat, `0x05`: Close |
| **Nonce** | 8 bytes (u64-BE) | Monotont økende sekvensnummer per retning for ChaCha20-Poly1305 og anti-replay |
| **Payload** | N bytes | Kryptert innhold etterfulgt av 16-byte Poly1305 autentiseringstag |

---

## Installasjon & Kompilering

Sørg for at du har Rust installert (krever Rust 1.75+):

```bash
# Klon repoet og bygg release-binæren
cargo build --release
```

---

## Brukerveiledning (CLI)

### 1. Generer nøkkelpar for server
```bash
cargo run -- keygen
```
Dette returnerer en privat nøkkel (som serveren må holde hemmelig) og en offentlig nøkkel (som deles med klienter).

### 2. Start serveren
```bash
# Start server på port 8080 med serverens private nøkkel
cargo run -- server --bind 127.0.0.1:8080 --private-key <SERVER_PRIVKEY_HEX>
```

### 3. Koble til med klienten (Enkeltmelding)
```bash
# Koble til serveren og send én melding
cargo run -- client --connect 127.0.0.1:8080 --server-pubkey <SERVER_PUBKEY_HEX> --message "Hemmelig melding over kryptert tunnel!"
```

### 4. Interaktiv E2EE Sesjon (Live REPL & Streaming)
```bash
# Start interaktiv modus med live chat og heartbeat-støtte
cargo run -- client --connect 127.0.0.1:8080 --server-pubkey <SERVER_PUBKEY_HEX> --interactive
```
I interaktiv modus:
- Skriv `/ping` for å sende kryptert heartbeat.
- Skriv tekster for å sende kryptert data frem og tilbake.
- Skriv `/quit` eller `exit` for å lukke sesjonen trygt.

### 5. Kjør integrerte krypto- og sårbarhetstester
```bash
# Verifiser handshake, manipuleringsforsvar (MAC failure) og replay-angrep
cargo run -- verify
```

---

## Bibliotek-API og Eksempelbruk (Rust API)

`noise-tunnel-rs` kan benyttes som et modulært bibliotek i andre prosjekter:

```rust
use noise_tunnel_rs::{TunnelClient, TunnelServer, KeyPair, SessionKeys, WireFrame, ReplayFilter};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Generer eller last nøkkelpar
    let server_keypair = KeyPair::generate();
    let _restored_keypair = KeyPair::from_private_slice(server_keypair.private_slice())?;
    let server_addr = "127.0.0.1:8080".parse()?;

    // 2. Start server med tilpasset prologue og forbindelsesgrense
    let server = TunnelServer::new(server_keypair.clone(), server_addr)
        .with_prologue_str("MyEnterpriseApp_v1")
        .with_max_connections(100);
    assert!(!server.has_active_connections());
    assert!(!server.is_at_capacity());

    // 3. Konfigurer klient med matchende prologue og timeout
    let client = TunnelClient::new(server_keypair.public_key, server_addr)
        .with_prologue_str("MyEnterpriseApp_v1")
        .with_timeout(Duration::from_secs(5));
    assert!(client.has_timeout());

    // 4. Send kryptert melding
    // let response = client.send_secure_message("Hemmelig hilsen").await?;

    // 5. Zero-I/O / Binær ramme-parsing, payload_slice og buffer-gjenbruk
    let frame = WireFrame::data(0, b"Kryptert innhold".to_vec());
    assert!(frame.is_data());
    assert_eq!(frame.payload_slice(), b"Kryptert innhold");

    let mut buffer = Vec::new();
    frame.serialize_into(&mut buffer);

    let parsed_frame = WireFrame::from_bytes(&buffer)?;
    assert_eq!(parsed_frame, frame);

    // 6. Anti-replay filter med Display og sanntidsmetrikker
    let mut replay_filter = ReplayFilter::new();
    replay_filter.validate_and_record(0)?;
    assert_eq!(replay_filter.total_accepted(), 1);
    println!("Filterstatus: {}", replay_filter);

    Ok(())
}
```

---

## Ytelse & Benchmarking

Kjør den integrerte ytelses-benchmarken:

```bash
cargo run --example benchmark
```

Typiske ytelsesresultater på moderne maskinvare:
- **ChaCha20-Poly1305 AEAD**: ~2.3 GB/s (18+ Gbps) krypteringshastighet
- **X25519 Diffie-Hellman**: ~58 000 nøkkelutvekslinger / sek
- **HKDF-SHA256**: ~1.4 millioner sesjonsavledninger / sek
- **Anti-Replay Window Filter**: ~40+ millioner pakkevalideringer / sek
- **Wire Framing Serialisering (Buffer-gjenbruk)**: Null ny-allokering med `serialize_into`

---

## Kjøre enhetstester & integrasjonstester

```bash
# Kjør alle enhetstester og integrasjonstester
cargo test --all-targets --verbose
```

---

## Sikkerhetsbetraktninger

1. **Autentisering av Server:** Klienten krever serverens forhåndsdistribuerte offentlige nøkkel (`server-pubkey`) for å forhindre Man-in-the-Middle (MitM)-angrep under handshake.
2. **Ephemerality (PFS):** Hver ny tilkobling genererer nye engangsnøkler (`e_c`, `e_s`). Selv om en nøkkel kompromitteres i fremtiden, kan ikke tidligere trafikk dekrypteres.
3. **AEAD Mac Verifikasjon:** Hvert datapakke-segment verifiseres med en 16-byte Poly1305 MAC-tag før dekryptering aksepteres.
4. **Glidevindu mot Replay:** Innebygd 128-bit bitmap-filter hindrer gjentatte pakkeangrep med sanntids-statistikk og null allokerings-overhead.
5. **Zeroization:** `KeyPair` og `SessionKeys` implementerer `zeroize::ZeroizeOnDrop` for umiddelbar overskriving av minne ved destruksjon.
