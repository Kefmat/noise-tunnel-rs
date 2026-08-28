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
