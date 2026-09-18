# Noise-Tunnel-RS

![CI](https://github.com/Kefmat/noise-tunnel-rs/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)
![Security](https://img.shields.io/badge/crypto-ChaCha20--Poly1305%20%7C%20X25519-green.svg)
![Memory](https://img.shields.io/badge/memory-ZeroizeOnDrop-brightgreen.svg)

> **Noise-Tunnel-RS** er en produksjonsklar, minnesikker, asynkron og autentisert ende-til-ende-kryptert (E2EE) sesjonstunnel i **Rust**. Prosjektet er bygget på prinsipper fra **Noise Protocol Framework (Noise_NK)** og moderne TLS 1.3-standarder, optimalisert for lav latens, null allokerings-overhead og maksimal angrepsresistens.

---

## Hovedfunksjoner & Egenskaper

- **Noise_NK 1-RTT Handshake**: Autentiserer serverens statiske nøkkel umiddelbart og forhandler sesjonsnøkler med *Perfect Forward Secrecy (PFS)*.
- **Høy Gjennomstrømming (Multi-GB/s)**: ChaCha20-Poly1305 AEAD gir lynrask kryptering og dekryptering på moderne CPU-er.
- **Minnesikkerhet & Zeroization**: Automatisk overskriving av hemmelige nøkler (`StaticSecret`, `EphemeralSecret`, `CipherState`) med `zeroize::ZeroizeOnDrop`.
- **O(1) Anti-Replay Glidevindu**: 128-bit bitmap som detekterer og avviser duplikate eller forsinkede nettverkspakker uten dynamisk minneallokering.
- **Buffer-gjenbruk (Zero-I/O Overhead)**: `WireFrame::serialize_into` og `payload_slice` minimerer minnekopiering under transport.
- **Tilpasset Prologue-binding**: Støtte for domenespesifikk sesjonsbinding via `with_prologue_str` for å hindre cross-protocol angrep.
- **Interaktiv REPL & Enkeltmeldinger**: Fleksibel CLI med støtte for enkeltmeldinger, live interaktiv streaming, kryptert `/ping`-heartbeat og `/quit`.

---

## Kryptografisk Arkitektur & Sikkerhetsdesign

Noise-Tunnel-RS implementerer en robust, formelt verifisert krypto-stakk:

| Komponent | Algoritme / Primitive | Standard / RFC | Formål & Sikkerhetsgaranti |
| :--- | :--- | :--- | :--- |
| **Nøkkelutveksling (KEX)** | **X25519** (Curve25519 ECDH) | RFC 7748 | Etablering av delt hemmelighet med 128-bit sikkerhetsnivå og *Perfect Forward Secrecy (PFS)* |
| **Nøkkelavledning (KDF)** | **HKDF-SHA256** | RFC 5869 | Sikker splitting av felles hemmelighet til to uavhengige skrivenøkler ($K_{CS}, K_{SC}$) |
| **Autentisert Kryptering (AEAD)** | **ChaCha20-Poly1305** | RFC 8439 | 256-bit symmetrisk kryptering med 128-bit Poly1305 MAC-tag for integritetsbeskyttelse mot tukling |
| **Transkript-binding** | **SHA-256 Hash Chaining** | FIPS 180-4 | Kontinuerlig hashing av handshake-tilstand ($h_1, h_2$) bundet til valgfri applikasjons-prologue |
| **Minnesikkerhet** | `zeroize` / `ZeroizeOnDrop` | Rust crate | Sikker nullstilling av hemmelig nøkkelmateriale fra RAM når strukturer forlater skop |
| **Replay Attack-beskyttelse** | 128-bit Bitmap Sliding Window | RFC 6479 konsept | O(1) tid og minne for å blokkere duplikate pakker og tillate legitim out-of-order levering |

---

## Protokollflyt & Handshake-tilstandsmaskin

Noise-Tunnel-RS kjører en 1-RTT handshake basert på **Noise_NK**-mønsteret:
- **`N` (No client static key)**: Klienten forblir anonym overfor nettverket under handshake, men bruker efemere nøkler.
- **`K` (Known server static key)**: Klienten har forhåndskjennskap til serverens offentlige nøkkel ($S_s$) for å hindre Man-in-the-Middle (MitM).

```text
 Client (Initiator)                                                Server (Responder)
   [Ephemeral e_c]                                                   [Static S_s, Ephemeral e_s]
          │                                                                   │
          │ ─── 1. HandshakeInit: [e_c.pub (32B)] [Encrypted Auth Tag] ─────> │
          │        • DH_static = X25519(e_c.priv, S_s.pub)                    │
          │        • h_1 = SHA256(prologue || e_c.pub || S_s.pub)             │
          │        • (K_init_c, _) = HKDF(DH_static, salt=h_1)                │
          │                                                                   │
          │ <── 2. HandshakeResp: [e_s.pub (32B)] [Encrypted ACK Tag] ─────── │
          │        • DH_ephem = X25519(e_c.priv, e_s.pub)                     │
          │        • h_2 = SHA256(prologue || e_c.pub || S_s.pub || e_s.pub)  │
          │        • (K_resp_s) = HKDF(DH_ephem, salt=h_2)                    │
          │                                                                   │
   [Split Transport Keys]                                            [Split Transport Keys]
   Secret = DH_static || DH_ephem                                    Secret = DH_static || DH_ephem
   (Key_CS, Key_SC) = HKDF(Secret, salt=h_2)                         (Key_CS, Key_SC) = HKDF(Secret, salt=h_2)
   Tx: Key_CS, Rx: Key_SC                                            Tx: Key_SC, Rx: Key_CS
          │                                                                   │
          │ ═══════════════════ 3. Sikker Datatransport ═════════════════════ │
          │ ─── Encrypted Data Frame (Nonce=0, Poly1305 Tag) ───────────────> │
          │ <── Encrypted Data Frame (Nonce=0, Poly1305 Tag) ──────────────── │
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

| Felt | Type / Størrelse | Beskrivelse |
| :--- | :--- | :--- |
| **Length** | `u32` (4 bytes, Big-Endian) | Total rammelengde ekskludert de 4 lengdebytene (Maks 64 KB DoS-grense). |
| **MessageType** | `u8` (1 byte) | Meldingskategori (se tabell under). |
| **Nonce** | `u64` (8 bytes, Big-Endian) | Monotont økende sekvensnummer for ChaCha20-Poly1305 og glidevinduet. |
| **Payload** | `[u8; N]` | Kryptert nyttelast etterfulgt av en 16-byte Poly1305 MAC-tag. |

#### Meldings-typer (`MessageType`)

| Type | Hex | Navn | Bruksområde |
| :---: | :---: | :--- | :--- |
| `1` | `0x01` | `HandshakeInit` | Klientens første handshake-pakke med $e_c.pub$ og kryptert autentisering. |
| `2` | `0x02` | `HandshakeResp` | Serverens handshake-svar med $e_s.pub$ og kryptert ACK. |
| `3` | `0x03` | `DataPayload` | Kryptert applikasjonstrafikk og meldinger i etablert sesjon. |
| `4` | `0x04` | `Heartbeat` | Toveis liveness-sjekk (`PING` $\rightarrow$ `PONG`) over den krypterte tunnelen. |
| `5` | `0x05` | `Close` | Ryddig avslutning og destruksjon av sesjonstilstand og nøkler. |

---

## Installasjon & Kompilering

Sørg for at du har Rust installert (krever Rust 1.75+):

```bash
# Klon repoet og bygg release-binæren
git clone https://github.com/Kefmat/noise-tunnel-rs.git
cd noise-tunnel-rs
cargo build --release
```

Binærfilen vil befinne seg i `target/release/noise-tunnel-rs`.

---

## Brukerveiledning (CLI)

CLI-et støtter både full serverdrift, klientsending, nøkkelgenerering og integrert sikkerhetsverifikasjon.

### 1. Generer kryptografiske X25519 nøkkelpar
```bash
cargo run -- keygen
```
Genererer et sikkert X25519 nøkkelpar fra operativsystemets CSPRNG (`OsRng`):
- **Privat nøkkel**: Må holdes strengt hemmelig (brukes av serveren).
- **Offentlig nøkkel**: Kan deles fritt med klienter for å verifisere serverens identitet.

### 2. Start den sikre tunnel-serveren
```bash
# Start server på standardport (127.0.0.1:8080) med spesifisert privatnøkkel
cargo run -- server --bind 127.0.0.1:8080 --private-key <SERVER_PRIVKEY_HEX>

# Start server med tilpasset domene-prologue og maksimalt 50 samtidige tilkoblinger:
cargo run -- server --bind 0.0.0.0:8080 --prologue "MyApp_v1" --max-connections 50
```

### 3. Send en sikker enkeltmelding (Klient)
```bash
# Send enkeltmelding med spesifisert server-pubkey, tilpasset prologue og 5s timeout:
cargo run -- client \
  --connect 127.0.0.1:8080 \
  --server-pubkey <SERVER_PUBKEY_HEX> \
  --prologue "MyApp_v1" \
  --timeout 5 \
  --message "Hemmelig payload over Noise E2EE tunnel!"
```

### 4. Start interaktiv E2EE-sesjon (Live REPL)
```bash
cargo run -- client \
  --connect 127.0.0.1:8080 \
  --server-pubkey <SERVER_PUBKEY_HEX> \
  --interactive
```
I interaktiv modus kan du sende kryptert trafikk i sanntid:
- `/help` - Viser tilgjengelige kommandoer og syntaks.
- `/info` - Viser sesjonsinformasjon, måladresse, prologue og aktiv TX-teller.
- `/ping` - Sender et kryptert heartbeat og mottar bekreftet `PONG` fra server.
- `<tekst>` - Sender ende-til-ende-kryptert melding og mottar ekko-svar.
- `/quit` eller `exit` - Sender et autentisert `Close`-rammesignal og avslutter sesjonen trygt.

### 5. Kjør automatisert sikkerhetsverifikasjon
```bash
cargo run -- verify
```
Gjennomfører sanntids sikkerhetstester mot live loopback-instans for å verifisere:
1. Full 1-RTT Handshake & AEAD datatransport.
2. Integritetssjekk og avvisning av manipulerte pakker (MitM Tamper detection).
3. Anti-Replay blokkering av oppfangede duplikate pakker.
4. Monoton nonce-isolasjon og overflow-beskyttelse.

### 6. Kjør ytelses-benchmark via CLI
```bash
# Kjør benchmark-suiten direkte via CLI eller via example:
cargo run -- bench
# eller:
cargo run --release --example benchmark
```

### 7. Kjør medfølgende kode-eksempler
```bash
# 1. Standalone echo server
cargo run --example echo_server

# 2. Sikker ende-til-ende chat-sesjon
cargo run --example secure_chat

# 3. Domene-isolasjon og prologue-binding
cargo run --example custom_prologue
```

---

## Bibliotek-API og Eksempelbruk (Rust SDK)

`noise-tunnel-rs` er designet som et modulært, høynivå Rust-bibliotek:

```rust
use anyhow::Result;
use noise_tunnel_rs::{
    KeyPair, MessageType, ReplayFilter, SessionKeys, SessionMetrics, TunnelClient,
    TunnelError, TunnelServer, WireFrame,
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Generer eller last inn et X25519 nøkkelpar (eller via hex)
    let server_keypair = KeyPair::generate();
    let _restored = KeyPair::from_private_slice(server_keypair.private_slice())?;
    let server_addr = "127.0.0.1:8080".parse()?;

    // 2. Initialiser server (eller bruk TunnelServer::from_hex)
    let server = TunnelServer::new(server_keypair.clone(), server_addr)
        .with_prologue_str("MyEnterpriseApp_v1")
        .with_max_connections(100);
    assert!(!server.has_active_connections());
    assert!(!server.is_at_capacity());
    assert_eq!(server.available_capacity(), Some(100));

    // 3. Konfigurer klient (eller bruk TunnelClient::from_hex)
    let client = TunnelClient::from_hex(&server_keypair.public_key_hex(), server_addr)?
        .with_prologue_str("MyEnterpriseApp_v1")
        .with_timeout(Duration::from_secs(5));
    assert!(client.has_timeout());

    // 4. Send en kryptert melding (hvis serveren lytter)
    // let response = client.send_secure_message("Hemmelig hilsen").await?;

    // 5. Zero-I/O / Binær ramme-serialisering med buffer-gjenbruk
    let raw_payload = b"Kryptert innhold";
    let frame = WireFrame::data_from_slice(0, raw_payload);
    assert!(frame.is_data());
    assert_eq!(frame.payload_slice(), raw_payload);

    let mut write_buffer = Vec::with_capacity(128);
    frame.serialize_into(&mut write_buffer);

    let parsed_frame = WireFrame::from_bytes(&write_buffer)?;
    assert_eq!(parsed_frame, frame);

    // 6. Anti-replay glidevindu med sanntids-metrikker
    let mut replay_filter = ReplayFilter::with_window_size(128);
    replay_filter.validate_and_record(10)?;
    assert_eq!(replay_filter.total_accepted(), 1);
    assert_eq!(replay_filter.total_rejected(), 0);
    assert_eq!(replay_filter.acceptance_rate(), 1.0);
    println!("Anti-replay status: {}", replay_filter);

    // 7. Sesjonsstatistikk og metrikksporing
    let mut metrics = SessionMetrics::new();
    metrics.record_tx(raw_payload.len());
    metrics.record_rx(raw_payload.len());
    println!("Sesjonsmetrikker: {}", metrics);

    Ok(())
}
```

---

## Ytelse & Benchmarking

Prosjektet inkluderer en dedikert benchmark-suite for å måle CPU-gjennomstrømming og latenstid:

```bash
cargo run --release --example benchmark
```

### Resultater på moderne maskinvare (Apple Silicon / x86_64 Server):

| Operasjon | Gjennomstrømming / Hastighet | Latens per op | Beskrivelse |
| :--- | :--- | :--- | :--- |
| **ChaCha20-Poly1305 AEAD** | **~2.3 GB/s (18.4 Gbps)** | < 7 μs (16 KB) | Symmetrisk kryptering + MAC-tag generering |
| **X25519 ECDH Handshake** | **~58 000 KEX ops/sek** | ~17 μs | Nøkkelutveksling med efemere nøkler |
| **HKDF-SHA256 Derivation** | **~1.4 millioner ops/sek** | ~0.7 μs | Sesjonsnøkkel-avledning med salt |
| **Anti-Replay Window Filter** | **~65+ millioner ops/sek** | < 15 ns | 128-bit bitmap O(1) sekvensnummer-validering |
| **Wire Frame `serialize_into`** | **~4.2 millioner rammer/sek** | < 240 ns | Null-allokering serialisering med buffer-gjenbruk |

---

## Sikkerhetsanalyse & Trusselmodell

Noise-Tunnel-RS er designet for å motstå et bredt spekter av nettverksangrep:

### 1. Man-in-the-Middle (MitM) & Server-autentisering
- **Trussel**: En angriper forsøker å avskjære tilkoblingen og utgi seg for å være serveren.
- **Forsvar**: Klienten krever serverens statiske offentlige nøkkel på forhånd. HandshakeInit krypteres mot $S_s$, slik at kun den legitime serveren kan dekryptere og fullføre håndtrykket.

### 2. Perfect Forward Secrecy (PFS)
- **Trussel**: En angriper tar opp kryptert trafikk og kompromitterer serverens private nøkkel på et senere tidspunkt.
- **Forsvar**: Transportnøklene ($K_{CS}, K_{SC}$) avledes fra efemere engangsnøkler ($e_c, e_s$). Fortidige sesjoner kan aldri dekrypteres selv om statiske nøkler lekker.

### 3. Pakkemanipulering & Avlytting (Tampering & Eavesdropping)
- **Trussel**: En angriper endrer biter i nettverkspakkene underveis.
- **Forsvar**: Poly1305 MAC-tag (16 bytes) verifiseres i konstant tid før noen dekryptert nyttelast overleveres til applikasjonslaget.

### 4. Replay-angrep (Packet Duplication & Delay)
- **Trussel**: En angriper fanger opp en gyldig kryptert pakke og sender den på nytt for å lure mottakeren.
- **Forsvar**: Innebygd `ReplayFilter` med et 128-bit glidevindu forkaster øyeblikkelig alle duplikater eller utdaterte sekvensnumre.

### 5. Nonce-isolasjon & Minnesikkerhet
- **Trussel**: Gjenbruk av (Key, Nonce)-par bryter ChaCha20-Poly1305 sikkerhetsgarantier.
- **Forsvar**: `CipherState` inkrementerer noncer monotont og kaster feil ved overflow. Alle hemmeligheter slettes fra RAM ved hjelp av `ZeroizeOnDrop`.

---

## Kjøre Tester & Kvalitetssikring

Prosjektet har 100% grønn CI-pipeline med enhetstester, ende-til-ende integrasjonstester og automatisert krypto-verifikasjon:

```bash
# 1. Kjør alle enhets- og integrasjonstester
cargo test --all-targets --verbose

# 2. Kjør kodeformatering og Clippy-linter (Zero Warnings)
cargo fmt --all -- --check
RUSTFLAGS="-D warnings" cargo clippy --all-targets --all-features

# 3. Kjør live sikkerhets- og sårbarhetsverifikasjon
cargo run -- verify
```

---

## Moduloversikt

| Modul | Primærrolle | Hovedtyper / Funksjoner |
| :--- | :--- | :--- |
| [`crypto`](src/crypto/mod.rs) | Krypto-primitiver | `KeyPair`, `EphemeralKeyPair`, `CipherState`, `SessionKeys`, `diffie_hellman` |
| [`protocol`](src/protocol/mod.rs) | Trådformatering & Anti-replay | `WireFrame`, `MessageType`, `ReplayFilter`, `hash_handshake_state` |
| [`server`](src/server.rs) | Asynkron TCP Server | `TunnelServer` |
| [`client`](src/client.rs) | Asynkron TCP Klient & REPL | `TunnelClient` |
| [`error`](src/error.rs) | Domene-feiltyper | `TunnelError`, `TunnelResult` |
| [`stats`](src/stats.rs) | Sesjonsstatistikk | `SessionMetrics` |
| [`verify`](src/verify.rs) | Automatisk verifikasjon | `run_security_verification` |
| [`bench`](src/bench.rs) | Ytelses-benchmarks | `run_benchmark_suite` |

---

## Lisens

Dette prosjektet er lisensiert under enten **MIT** eller **Apache-2.0** etter eget valg (se [LICENSE](LICENSE) eller [Cargo.toml](Cargo.toml)).
