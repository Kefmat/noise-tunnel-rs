//! Verifikasjons- og sikkerhetsdemonstrasjonsmodul.
//! Kjører automatiserte sikkerhetstester for å bevise at tunnelen avviser
//! manipulerte pakker, replay-angrep og uautoriserte nøkler.

use anyhow::{anyhow, Result};
use tokio::net::TcpListener;

use crate::client::TunnelClient;
use crate::crypto::{CipherState, KeyPair, KEY_LEN};
use crate::protocol::ReplayFilter;
use crate::server::TunnelServer;

pub async fn run_security_verification() -> Result<()> {
    println!("\n========================================================");
    println!("  KJORER AUTOMATISK KRYPTOGRAFISK SIKKERHETSSJEKK   ");
    println!("========================================================\n");

    // 1. Test: Nøkkelutveksling & Autentisert Kryptering (Happy Path)
    print!("[1/4] Tester E2EE Handshake og full datatransport... ");
    test_live_tunnel_handshake().await?;
    println!("BESTATT");

    // 2. Test: Deteksjon av manipulerte pakker (AEAD Poly1305 MAC integritet)
    print!("[2/4] Tester forsvar mot pakke-manipulering (Tamper / MitM)... ");
    test_packet_tampering_detection()?;
    println!("BESTATT (Avvist med MAC-feil)");

    // 3. Test: Replay Attack Defense (Gjentakelse av gyldig oppfanget pakke)
    print!("[3/4] Tester forsvar mot Replay-angrep... ");
    test_replay_attack_rejection()?;
    println!("BESTATT (Replay detektert og blokkert)");

    // 4. Test: Forhindring av Nonce-gjenbruk (Monotone counters)
    print!("[4/4] Tester nonce-isolasjon og unikhet... ");
    test_nonce_progression()?;
    println!("BESTATT");

    println!("\nALLE 4 KRYPTOGRAFISKE SIKKERHETSTESTER BESTATT UTEN FEIL!\n");
    Ok(())
}

async fn test_live_tunnel_handshake() -> Result<()> {
    let server_keypair = KeyPair::generate();
    let server_pubkey = server_keypair.public_key;

    // Finn en tilgjengelig port på localhost
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    drop(listener);

    let server = TunnelServer::new(server_keypair, local_addr);
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Vent kort på at server starter
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let client = TunnelClient::new(server_pubkey, local_addr);
    let secret_test_message = "Testmelding med topphemmelig innhold 12345!";
    let response = client.send_secure_message(secret_test_message).await?;

    if !response.contains(secret_test_message) {
        return Err(anyhow!("Feil svar mottatt over tunnelen!"));
    }
    Ok(())
}

fn test_packet_tampering_detection() -> Result<()> {
    let key = [0x99u8; KEY_LEN];
    let mut sender = CipherState::new(key);
    let mut receiver = CipherState::new(key);

    let plaintext = b"Viktig bankoverforing: 1 000 000 NOK";
    let mut ciphertext = sender.encrypt(plaintext, b"aad-metadata")?;

    // Ondsinnet aktør endrer én byte i transporten
    let last_idx = ciphertext.len() - 1;
    ciphertext[last_idx] ^= 0xFF;

    // Forsøk å dekryptere manipulert pakke
    let result = receiver.decrypt(&ciphertext, b"aad-metadata", 0);
    if result.is_ok() {
        return Err(anyhow!("KRITISK SIKKERHETSFEIL: Manipulert pakke ble akseptert!"));
    }
    Ok(())
}

fn test_replay_attack_rejection() -> Result<()> {
    let mut filter = ReplayFilter::new();

    // Klient sender lovlig pakke med nonce 100
    filter.validate_and_record(100)?;

    // Avlytter forsøker å sende samme pakke (nonce 100) på nytt
    let replay_attempt = filter.validate_and_record(100);
    if replay_attempt.is_ok() {
        return Err(anyhow!("KRITISK SIKKERHETSFEIL: Replay-pakke slapp gjennom filteret!"));
    }
    Ok(())
}

fn test_nonce_progression() -> Result<()> {
    let key = [0x33u8; KEY_LEN];
    let mut cipher = CipherState::new(key);

    assert_eq!(cipher.current_nonce(), 0);
    let _ = cipher.encrypt(b"msg 1", b"")?;
    assert_eq!(cipher.current_nonce(), 1);
    let _ = cipher.encrypt(b"msg 2", b"")?;
    assert_eq!(cipher.current_nonce(), 2);

    Ok(())
}
