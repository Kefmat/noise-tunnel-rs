use anyhow::Result;
use noise_tunnel_rs::client::TunnelClient;
use noise_tunnel_rs::crypto::KeyPair;
use noise_tunnel_rs::server::TunnelServer;
use tokio::net::TcpListener;

async fn spawn_test_server() -> Result<(KeyPair, std::net::SocketAddr)> {
    let server_keypair = KeyPair::generate();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    drop(listener);

    let server = TunnelServer::new(server_keypair.clone(), local_addr);
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Gi serveren litt tid til å binde sokkelen
    tokio::time::sleep(tokio::time::Duration::from_millis(60)).await;
    Ok((server_keypair, local_addr))
}

#[tokio::test]
async fn test_concurrent_sessions() -> Result<()> {
    let (server_keypair, server_addr) = spawn_test_server().await?;

    let mut handles = Vec::new();
    for i in 0..5 {
        let pubkey = server_keypair.public_key;
        let addr = server_addr;
        let handle = tokio::spawn(async move {
            let client = TunnelClient::new(pubkey, addr);
            let msg = format!("Samtidig sesjons-test fra klient #{}", i);
            let resp = client.send_secure_message(&msg).await.unwrap();
            assert!(resp.contains(&msg));
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    Ok(())
}

#[tokio::test]
async fn test_wrong_server_pubkey_fails_handshake() -> Result<()> {
    let (_server_keypair, server_addr) = spawn_test_server().await?;

    // Klient bruker en tilfeldig ugyldig server-nøkkel
    let attacker_fake_keypair = KeyPair::generate();
    let client = TunnelClient::new(attacker_fake_keypair.public_key, server_addr);

    let result = client.send_secure_message("Skal feile handshake").await;
    assert!(
        result.is_err(),
        "Handshake med ugyldig server public key må feile!"
    );

    Ok(())
}

#[tokio::test]
async fn test_large_payload_transfer() -> Result<()> {
    let (server_keypair, server_addr) = spawn_test_server().await?;

    let client = TunnelClient::new(server_keypair.public_key, server_addr);
    let large_message = "A".repeat(32 * 1024); // 32 KB payload

    let response = client.send_secure_message(&large_message).await?;
    assert!(response.contains(&large_message));

    Ok(())
}

#[tokio::test]
async fn test_sequential_messages() -> Result<()> {
    let (server_keypair, server_addr) = spawn_test_server().await?;
    let client = TunnelClient::new(server_keypair.public_key, server_addr);

    for i in 1..=10 {
        let msg = format!("Sekvensiell testmelding #{}", i);
        let response = client.send_secure_message(&msg).await?;
        assert!(response.contains(&msg));
    }

    Ok(())
}

#[tokio::test]
async fn test_empty_payload_transfer() -> Result<()> {
    let (server_keypair, server_addr) = spawn_test_server().await?;
    let client = TunnelClient::new(server_keypair.public_key, server_addr);

    let response = client.send_secure_message("").await?;
    assert_eq!(response, "Server mottok: ");

    Ok(())
}

#[tokio::test]
async fn test_hex_configured_client_server() -> Result<()> {
    let server_keypair = KeyPair::generate();
    let priv_hex = server_keypair.private_key_hex();
    let pub_hex = server_keypair.public_key_hex();

    let server_keys = KeyPair::from_private_hex(&priv_hex)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    drop(listener);

    let server = TunnelServer::new(server_keys, local_addr);
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(60)).await;

    let client_pubkey = KeyPair::parse_public_key_hex(&pub_hex)?;
    let client = TunnelClient::new(client_pubkey, local_addr);

    let resp = client
        .send_secure_message("Ende-til-ende test med hex-konfigurerte nøkler")
        .await?;
    assert!(resp.contains("Ende-til-ende test med hex-konfigurerte nøkler"));

    Ok(())
}

#[tokio::test]
async fn test_heartbeat_and_session_lifecycle() -> Result<()> {
    use noise_tunnel_rs::crypto::{derive_session_keys, CipherState, EphemeralKeyPair, KEY_LEN};
    use noise_tunnel_rs::protocol::{hash_handshake_state, MessageType, WireFrame, PROTOCOL_NAME};
    use tokio::net::TcpStream;

    let (server_keypair, server_addr) = spawn_test_server().await?;
    let mut stream = TcpStream::connect(server_addr).await?;

    // Perform handshake manually to test transport heartbeat & close lifecycle
    let client_ephem = EphemeralKeyPair::generate();
    let dh_static = client_ephem.diffie_hellman(&server_keypair.public_key);
    let h1 = hash_handshake_state(
        PROTOCOL_NAME,
        &client_ephem.public_key,
        &server_keypair.public_key,
        None,
    );

    let (k_init_c, _) = derive_session_keys(&dh_static, &h1)?;
    let mut init_cipher = CipherState::new(k_init_c);
    let init_ciphertext = init_cipher.encrypt(b"HANDSHAKE_INIT_CLIENT", &h1)?;

    let mut init_payload = Vec::new();
    init_payload.extend_from_slice(&client_ephem.public_key);
    init_payload.extend_from_slice(&init_ciphertext);

    let init_frame = WireFrame::new(MessageType::HandshakeInit, 0, init_payload);
    init_frame.write_to(&mut stream).await?;

    // Read HandshakeResp
    let resp_frame = WireFrame::read_from(&mut stream).await?;
    assert_eq!(resp_frame.msg_type, MessageType::HandshakeResp);

    let mut server_ephem_pub = [0u8; KEY_LEN];
    server_ephem_pub.copy_from_slice(&resp_frame.payload[..KEY_LEN]);
    let resp_ciphertext = &resp_frame.payload[KEY_LEN..];

    let dh_ephem = client_ephem.diffie_hellman(&server_ephem_pub);
    let h2 = hash_handshake_state(
        PROTOCOL_NAME,
        &client_ephem.public_key,
        &server_keypair.public_key,
        Some(&server_ephem_pub),
    );

    let (_, k_resp_s) = derive_session_keys(&dh_ephem, &h2)?;
    let mut resp_cipher = CipherState::new(k_resp_s);
    let ack = resp_cipher.decrypt(resp_ciphertext, &h2, 0)?;
    assert_eq!(ack, b"HANDSHAKE_COMPLETE_ACK");

    let mut combined_secret = Vec::with_capacity(KEY_LEN * 2);
    combined_secret.extend_from_slice(&dh_static);
    combined_secret.extend_from_slice(&dh_ephem);

    let (client_write_key, server_write_key) = derive_session_keys(&combined_secret, &h2)?;
    let mut tx = CipherState::new(client_write_key);
    let mut rx = CipherState::new(server_write_key);

    // Send Heartbeat
    let ping_ciphertext = tx.encrypt(b"PING", b"heartbeat")?;
    let ping_frame = WireFrame::new(MessageType::Heartbeat, 0, ping_ciphertext);
    ping_frame.write_to(&mut stream).await?;

    // Receive Pong
    let pong_frame = WireFrame::read_from(&mut stream).await?;
    assert_eq!(pong_frame.msg_type, MessageType::Heartbeat);
    let decrypted_pong = rx.decrypt(&pong_frame.payload, b"heartbeat", pong_frame.nonce)?;
    assert_eq!(decrypted_pong, b"PONG");

    // Send Close
    let close_frame = WireFrame::new(MessageType::Close, tx.current_nonce(), vec![]);
    close_frame.write_to(&mut stream).await?;

    Ok(())
}

#[tokio::test]
async fn test_malformed_handshake_payload_rejected() -> Result<()> {
    use noise_tunnel_rs::protocol::{MessageType, WireFrame};
    use tokio::net::TcpStream;

    let (_server_keypair, server_addr) = spawn_test_server().await?;
    let mut stream = TcpStream::connect(server_addr).await?;

    // Send HandshakeInit with too short payload (< KEY_LEN + 16 = 48 bytes)
    let short_payload = vec![0x42u8; 10];
    let bad_init_frame = WireFrame::new(MessageType::HandshakeInit, 0, short_payload);
    bad_init_frame.write_to(&mut stream).await?;

    // Server should reject and close connection
    let read_result = WireFrame::read_from(&mut stream).await;
    assert!(
        read_result.is_err(),
        "Server må lukke tilkobling ved ugyldig handshake payload"
    );

    Ok(())
}

#[tokio::test]
async fn test_network_replay_packet_rejected() -> Result<()> {
    use noise_tunnel_rs::crypto::{derive_session_keys, CipherState, EphemeralKeyPair, KEY_LEN};
    use noise_tunnel_rs::protocol::{hash_handshake_state, MessageType, WireFrame, PROTOCOL_NAME};
    use tokio::net::TcpStream;

    let (server_keypair, server_addr) = spawn_test_server().await?;
    let mut stream = TcpStream::connect(server_addr).await?;

    // Handshake
    let client_ephem = EphemeralKeyPair::generate();
    let dh_static = client_ephem.diffie_hellman(&server_keypair.public_key);
    let h1 = hash_handshake_state(
        PROTOCOL_NAME,
        &client_ephem.public_key,
        &server_keypair.public_key,
        None,
    );

    let (k_init_c, _) = derive_session_keys(&dh_static, &h1)?;
    let mut init_cipher = CipherState::new(k_init_c);
    let init_ciphertext = init_cipher.encrypt(b"HANDSHAKE_INIT_CLIENT", &h1)?;

    let mut init_payload = Vec::new();
    init_payload.extend_from_slice(&client_ephem.public_key);
    init_payload.extend_from_slice(&init_ciphertext);

    let init_frame = WireFrame::new(MessageType::HandshakeInit, 0, init_payload);
    init_frame.write_to(&mut stream).await?;

    let resp_frame = WireFrame::read_from(&mut stream).await?;
    let mut server_ephem_pub = [0u8; KEY_LEN];
    server_ephem_pub.copy_from_slice(&resp_frame.payload[..KEY_LEN]);
    let dh_ephem = client_ephem.diffie_hellman(&server_ephem_pub);
    let h2 = hash_handshake_state(
        PROTOCOL_NAME,
        &client_ephem.public_key,
        &server_keypair.public_key,
        Some(&server_ephem_pub),
    );

    let mut combined_secret = Vec::with_capacity(KEY_LEN * 2);
    combined_secret.extend_from_slice(&dh_static);
    combined_secret.extend_from_slice(&dh_ephem);

    let (client_write_key, _server_write_key) = derive_session_keys(&combined_secret, &h2)?;
    let mut tx = CipherState::new(client_write_key);

    // Send original data frame (nonce 0)
    let original_ciphertext = tx.encrypt(b"Original packet", b"tunnel-data")?;
    let data_frame = WireFrame::new(MessageType::DataPayload, 0, original_ciphertext);
    data_frame.write_to(&mut stream).await?;

    // Server answers
    let reply = WireFrame::read_from(&mut stream).await?;
    assert_eq!(reply.msg_type, MessageType::DataPayload);

    // Replay attack: send EXACT duplicate data frame (nonce 0) again
    data_frame.write_to(&mut stream).await?;

    // Server ReplayFilter rejects the replayed packet and terminates session
    let post_replay_read = WireFrame::read_from(&mut stream).await;
    assert!(
        post_replay_read.is_err(),
        "Replay-pakke må føre til at serveren avviser sesjonen"
    );

    Ok(())
}

#[tokio::test]
async fn test_client_and_server_accessors() -> Result<()> {
    let keypair = KeyPair::generate();
    let addr: std::net::SocketAddr = "127.0.0.1:9999".parse()?;

    let server = TunnelServer::new(keypair.clone(), addr);
    assert_eq!(server.bind_addr(), addr);
    assert_eq!(server.public_key(), &keypair.public_key);
    assert_eq!(server.public_key_hex(), keypair.public_key_hex());

    let client = TunnelClient::new(keypair.public_key, addr);
    assert_eq!(client.target_addr(), addr);
    assert_eq!(client.server_pubkey(), &keypair.public_key);
    assert_eq!(client.server_pubkey_hex(), keypair.public_key_hex());

    Ok(())
}

#[tokio::test]
async fn test_multiple_rapid_heartbeats_in_session() -> Result<()> {
    use noise_tunnel_rs::crypto::{derive_session_keys, CipherState, EphemeralKeyPair, KEY_LEN};
    use noise_tunnel_rs::protocol::{hash_handshake_state, WireFrame, PROTOCOL_NAME};
    use tokio::net::TcpStream;

    let (server_keypair, server_addr) = spawn_test_server().await?;
    let mut stream = TcpStream::connect(server_addr).await?;

    // Handshake
    let client_ephem = EphemeralKeyPair::generate();
    let dh_static = client_ephem.diffie_hellman(&server_keypair.public_key);
    let h1 = hash_handshake_state(
        PROTOCOL_NAME,
        &client_ephem.public_key,
        &server_keypair.public_key,
        None,
    );

    let (k_init_c, _) = derive_session_keys(&dh_static, &h1)?;
    let mut init_cipher = CipherState::new(k_init_c);
    let init_ciphertext = init_cipher.encrypt(b"HANDSHAKE_INIT_CLIENT", &h1)?;

    let mut init_payload = Vec::new();
    init_payload.extend_from_slice(&client_ephem.public_key);
    init_payload.extend_from_slice(&init_ciphertext);

    let init_frame = WireFrame::handshake_init(0, init_payload);
    init_frame.write_to(&mut stream).await?;

    let resp_frame = WireFrame::read_from(&mut stream).await?;
    let mut server_ephem_pub = [0u8; KEY_LEN];
    server_ephem_pub.copy_from_slice(&resp_frame.payload[..KEY_LEN]);
    let dh_ephem = client_ephem.diffie_hellman(&server_ephem_pub);
    let h2 = hash_handshake_state(
        PROTOCOL_NAME,
        &client_ephem.public_key,
        &server_keypair.public_key,
        Some(&server_ephem_pub),
    );

    let (_, k_resp_s) = derive_session_keys(&dh_ephem, &h2)?;
    let mut resp_cipher = CipherState::new(k_resp_s);
    let ack = resp_cipher.decrypt(&resp_frame.payload[KEY_LEN..], &h2, 0)?;
    assert_eq!(ack, b"HANDSHAKE_COMPLETE_ACK");

    let mut combined_secret = Vec::with_capacity(KEY_LEN * 2);
    combined_secret.extend_from_slice(&dh_static);
    combined_secret.extend_from_slice(&dh_ephem);

    let (client_write_key, server_write_key) = derive_session_keys(&combined_secret, &h2)?;
    let mut tx = CipherState::new(client_write_key);
    let mut rx = CipherState::new(server_write_key);

    // Send 5 rapid heartbeats sequentially
    for seq in 0..5 {
        let nonce = tx.current_nonce();
        assert_eq!(nonce, seq);
        let ping_ciphertext = tx.encrypt(b"PING", b"heartbeat")?;
        let ping_frame = WireFrame::heartbeat(nonce, ping_ciphertext);
        ping_frame.write_to(&mut stream).await?;

        let pong_frame = WireFrame::read_from(&mut stream).await?;
        assert!(pong_frame.is_heartbeat());
        assert_eq!(pong_frame.nonce, seq);
        let decrypted_pong = rx.decrypt(&pong_frame.payload, b"heartbeat", pong_frame.nonce)?;
        assert_eq!(decrypted_pong, b"PONG");
    }

    // Follow up with regular data frame
    let tx_nonce = tx.current_nonce();
    let data_cipher = tx.encrypt(b"Data etter heartbeats", b"tunnel-data")?;
    let data_frame = WireFrame::data(tx_nonce, data_cipher);
    data_frame.write_to(&mut stream).await?;

    let reply_frame = WireFrame::read_from(&mut stream).await?;
    assert!(reply_frame.is_data());
    let decrypted_reply = rx.decrypt(&reply_frame.payload, b"tunnel-data", reply_frame.nonce)?;
    assert_eq!(
        String::from_utf8_lossy(&decrypted_reply),
        "Server mottok: Data etter heartbeats"
    );

    // Close
    let close_frame = WireFrame::close(tx.current_nonce());
    close_frame.write_to(&mut stream).await?;

    Ok(())
}
