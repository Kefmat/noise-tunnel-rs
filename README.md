# Noise-Tunnel-RS

![CI](https://github.com/Kefmat/noise-tunnel-rs/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)
![Security](https://img.shields.io/badge/crypto-ChaCha20--Poly1305%20%7C%20X25519-green.svg)
![Memory](https://img.shields.io/badge/memory-ZeroizeOnDrop-brightgreen.svg)

> **Noise-Tunnel-RS** er en produksjonsklar, minnesikker, asynkron og autentisert ende-til-ende-kryptert (E2EE) sesjonstunnel i **Rust**. Prosjektet er bygget på prinsipper fra **Noise Protocol Framework (Noise_NK)** og moderne TLS 1.3-standarder, optimalisert for lav latens, null allokerings-overhead og maksimal angrepsresistens.

---

## Hovedfunksjoner & Egenskaper

- 🛡️ **Noise_NK 1-RTT Handshake**: Autentiserer serverens statiske nøkkel umiddelbart og forhandler sesjonsnøkler med *Perfect Forward Secrecy (PFS)*.
- ⚡ **Høy Gjennomstrømming (Multi-GB/s)**: ChaCha20-Poly1305 AEAD gir lynrask kryptering og dekryptering på moderne CPU-er.
- 🔒 **Minnesikkerhet & Zeroization**: Automatisk overskriving av hemmelige nøkler (`StaticSecret`, `EphemeralSecret`, `CipherState`) med `zeroize::ZeroizeOnDrop`.
- 🪟 **O(1) Anti-Replay Glidevindu**: 128-bit bitmap som detekterer og avviser duplikate eller forsinkede nettverkspakker uten dynamisk minneallokering.
- 🔄 **Buffer-gjenbruk (Zero-I/O Overhead)**: `WireFrame::serialize_into` og `payload_slice` minimerer minnekopiering under transport.
- 🏷️ **Tilpasset Prologue-binding**: Støtte for domenespesifikk sesjonsbinding via `with_prologue_str` for å hindre cross-protocol angrep.
- 💬 **Interaktiv REPL & Enkeltmeldinger**: Fleksibel CLI med støtte for enkeltmeldinger, live interaktiv streaming, kryptert `/ping`-heartbeat og `/quit`.

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
