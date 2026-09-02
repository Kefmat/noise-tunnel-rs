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
