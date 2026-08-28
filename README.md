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
4. **Glidevindu mot Replay:** Innebygd 128-bit bitmap-filter hindrer gjentatte pakkeangrep med null allokerings-overhead.
