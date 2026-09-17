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

#[tokio::test]
async fn test_wireframe_from_bytes_integration() -> Result<()> {
    use noise_tunnel_rs::protocol::WireFrame;

    let frames = vec![
        WireFrame::handshake_init(0, vec![1, 2, 3, 4, 5]),
        WireFrame::handshake_resp(0, vec![6, 7, 8, 9, 10]),
        WireFrame::data(12345, b"Test payload bytes".to_vec()),
        WireFrame::heartbeat(999, b"PING".to_vec()),
        WireFrame::close(1000),
    ];

    for frame in frames {
        let serialized = frame.serialize();
        let parsed = WireFrame::from_bytes(&serialized)?;
        assert_eq!(parsed, frame);

        let try_parsed = WireFrame::try_from(serialized.as_slice())?;
        assert_eq!(try_parsed, frame);
    }

    Ok(())
}

#[tokio::test]
async fn test_client_server_builder_configs() -> Result<()> {
    let keypair = KeyPair::generate();
    let addr: std::net::SocketAddr = "127.0.0.1:8888".parse()?;

    // Server builder
    let server = TunnelServer::new(keypair.clone(), addr).with_max_connections(50);
    assert_eq!(server.max_connections(), Some(50));
    assert_eq!(server.active_connections(), 0);

    // Client builder
    let timeout = std::time::Duration::from_secs(5);
    let client = TunnelClient::new(keypair.public_key, addr).with_timeout(timeout);
    assert_eq!(client.timeout(), Some(timeout));

    // Live execution with configured client
    let (server_keys, server_addr) = spawn_test_server().await?;
    let live_client = TunnelClient::new(server_keys.public_key, server_addr)
        .with_timeout(std::time::Duration::from_secs(3));

    let reply = live_client
        .send_secure_message("Builder test med timeout")
        .await?;
    assert!(reply.contains("Builder test med timeout"));

    Ok(())
}

#[tokio::test]
async fn test_custom_prologue_agreement_and_mismatch() -> Result<()> {
    let server_keypair = KeyPair::generate();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    drop(listener);

    let custom_prologue = b"Noise_Custom_App_Namespace_v2";

    let server =
        TunnelServer::new(server_keypair.clone(), server_addr).with_prologue(custom_prologue);
    assert_eq!(server.prologue(), custom_prologue);

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(60)).await;

    // 1. Client with matching custom prologue -> Handshake succeeds
    let client_matching =
        TunnelClient::new(server_keypair.public_key, server_addr).with_prologue(custom_prologue);
    assert_eq!(client_matching.prologue(), custom_prologue);

    let res = client_matching
        .send_secure_message("Melding med tilpasset prologue")
        .await?;
    assert!(res.contains("Melding med tilpasset prologue"));

    // 2. Client with mismatched prologue -> Handshake fails due to transcript binding
    let client_mismatched = TunnelClient::new(server_keypair.public_key, server_addr)
        .with_prologue(b"Noise_Mismatch_Namespace_v1");

    let err_res = client_mismatched
        .send_secure_message("Skal feile pga feil prologue")
        .await;
    assert!(
        err_res.is_err(),
        "Handshake med uoverensstemmende prologue må feile!"
    );

    Ok(())
}

#[tokio::test]
async fn test_full_duplex_session_with_serialize_into_and_replay_stats() -> Result<()> {
    use noise_tunnel_rs::crypto::{derive_session_keys, CipherState, EphemeralKeyPair, KEY_LEN};
    use noise_tunnel_rs::protocol::{hash_handshake_state, ReplayFilter, WireFrame, PROTOCOL_NAME};
    use tokio::net::TcpStream;

    let (server_keypair, server_addr) = spawn_test_server().await?;
    let mut stream = TcpStream::connect(server_addr).await?;

    // Client handshake
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
    let mut write_buf = Vec::new();
    init_frame.serialize_into(&mut write_buf);
    use tokio::io::AsyncWriteExt;
    stream.write_all(&write_buf).await?;
    stream.flush().await?;

    // Read HandshakeResp
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
    let mut local_replay_filter = ReplayFilter::new();

    // Send 3 data frames reusing write buffer
    for i in 0..3 {
        let nonce = tx.current_nonce();
        let msg = format!("Buffer gjenbruk melding #{}", i);
        let ct = tx.encrypt(msg.as_bytes(), b"tunnel-data")?;
        let frame = WireFrame::data(nonce, ct);

        write_buf.clear();
        frame.serialize_into(&mut write_buf);
        stream.write_all(&write_buf).await?;
        stream.flush().await?;

        let reply = WireFrame::read_from(&mut stream).await?;
        assert!(reply.is_data());
        local_replay_filter.validate_and_record(reply.nonce)?;

        let decrypted = rx.decrypt(&reply.payload, b"tunnel-data", reply.nonce)?;
        assert_eq!(
            String::from_utf8_lossy(&decrypted),
            format!("Server mottok: {}", msg)
        );
    }

    assert_eq!(local_replay_filter.total_seen(), 3);
    assert_eq!(local_replay_filter.total_accepted(), 3);
    assert_eq!(local_replay_filter.total_rejected(), 0);

    // Close session
    let close = WireFrame::close(tx.current_nonce());
    write_buf.clear();
    close.serialize_into(&mut write_buf);
    stream.write_all(&write_buf).await?;
    stream.flush().await?;

    Ok(())
}

#[tokio::test]
async fn test_with_prologue_str_builder() -> Result<()> {
    let server_keypair = KeyPair::generate();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    drop(listener);

    let prologue_str = "Noise_String_Prologue_v1";

    let server =
        TunnelServer::new(server_keypair.clone(), server_addr).with_prologue_str(prologue_str);
    assert_eq!(server.prologue(), prologue_str.as_bytes());

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(60)).await;

    let client =
        TunnelClient::new(server_keypair.public_key, server_addr).with_prologue_str(prologue_str);
    assert_eq!(client.prologue(), prologue_str.as_bytes());

    let resp = client
        .send_secure_message("Tester with_prologue_str builder")
        .await?;
    assert!(resp.contains("Tester with_prologue_str builder"));

    Ok(())
}

#[tokio::test]
async fn test_capacity_and_timeout_query_helpers() -> Result<()> {
    let keypair = KeyPair::generate();
    let addr: std::net::SocketAddr = "127.0.0.1:7777".parse()?;

    // Server queries
    let server_unlimited = TunnelServer::new(keypair.clone(), addr);
    assert!(!server_unlimited.has_active_connections());
    assert!(!server_unlimited.is_at_capacity());

    let server_limited = TunnelServer::new(keypair.clone(), addr).with_max_connections(0);
    assert!(server_limited.is_at_capacity());

    // Client queries
    let client_no_timeout = TunnelClient::new(keypair.public_key, addr);
    assert!(!client_no_timeout.has_timeout());

    let client_with_timeout = client_no_timeout.with_timeout(std::time::Duration::from_secs(2));
    assert!(client_with_timeout.has_timeout());

    Ok(())
}

#[tokio::test]
async fn test_client_from_hex_and_timeout_millis() -> Result<()> {
    let keypair = KeyPair::generate();
    let addr: std::net::SocketAddr = "127.0.0.1:6543".parse()?;

    let client = TunnelClient::from_hex(&keypair.public_key_hex(), addr)?.with_timeout_millis(1500);

    assert_eq!(client.server_pubkey(), &keypair.public_key);
    assert_eq!(
        client.timeout(),
        Some(std::time::Duration::from_millis(1500))
    );
    assert!(client.has_timeout());

    // Ugyldig hex feiler
    assert!(TunnelClient::from_hex("invalid-hex", addr).is_err());

    Ok(())
}

#[tokio::test]
async fn test_server_from_hex() -> Result<()> {
    let keypair = KeyPair::generate();
    let addr: std::net::SocketAddr = "127.0.0.1:6544".parse()?;

    let server = TunnelServer::from_hex(&keypair.private_key_hex(), addr)?;
    assert_eq!(server.public_key(), &keypair.public_key);
    assert_eq!(server.public_key_hex(), keypair.public_key_hex());

    // Ugyldig hex feiler
    assert!(TunnelServer::from_hex("invalid-hex", addr).is_err());

    Ok(())
}

#[tokio::test]
async fn test_server_available_capacity_and_wireframe_data_from_slice() -> Result<()> {
    use noise_tunnel_rs::protocol::WireFrame;

    let keypair = KeyPair::generate();
    let addr: std::net::SocketAddr = "127.0.0.1:9191".parse()?;

    // Server available_capacity and reset_connections
    let server = TunnelServer::new(keypair.clone(), addr).with_max_connections(10);
    assert_eq!(server.available_capacity(), Some(10));
    assert_eq!(server.active_connections(), 0);

    server.reset_connections();
    assert_eq!(server.available_capacity(), Some(10));

    // WireFrame data_from_slice constructor
    let raw_slice = b"Integration test payload slice";
    let frame = WireFrame::data_from_slice(1234, raw_slice);
    assert_eq!(frame.nonce(), 1234);
    assert!(frame.is_data());
    assert_eq!(frame.payload_slice(), raw_slice);

    let serialized = frame.serialize();
    let parsed = WireFrame::from_bytes(&serialized)?;
    assert_eq!(parsed, frame);

    Ok(())
}

#[tokio::test]
async fn test_error_conversions_and_metrics_integration() -> Result<()> {
    use noise_tunnel_rs::{SessionMetrics, TunnelError};

    // TunnelError tests
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Nettverksfeil");
    let tunnel_err = TunnelError::from(io_err);
    assert!(matches!(tunnel_err, TunnelError::Io(_)));

    let custom_err = TunnelError::Timeout("Sesjon svarte ikke".to_string());
    assert!(custom_err.to_string().contains("Sesjon svarte ikke"));

    // SessionMetrics in live scenario
    let (server_keys, server_addr) = spawn_test_server().await?;
    let client = TunnelClient::new(server_keys.public_key, server_addr);

    let mut client_metrics = SessionMetrics::new();
    let msg = "Metrikk testmelding over tunnel";
    client_metrics.record_tx(msg.len());

    let reply = client.send_secure_message(msg).await?;
    client_metrics.record_rx(reply.len());

    assert_eq!(client_metrics.frames_sent(), 1);
    assert_eq!(client_metrics.frames_received(), 1);
    assert!(client_metrics.total_bytes() > 0);
    assert!(client_metrics.idle_duration() < std::time::Duration::from_secs(2));

    Ok(())
}
