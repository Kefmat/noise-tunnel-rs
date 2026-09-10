//! Ytelses- og throughput-benchmark for Noise-Tunnel-RS krypto- og rammeprosessering.

use noise_tunnel_rs::crypto::{derive_session_keys, diffie_hellman, CipherState, KeyPair, KEY_LEN};
use noise_tunnel_rs::protocol::{MessageType, ReplayFilter, WireFrame};
use std::time::Instant;

fn main() {
    println!("\n========================================================");
    println!("  NOISE-TUNNEL-RS KRYPTOGRAFISK BENCHMARK SUITE       ");
    println!("========================================================\n");

    // 1. X25519 ECDH Key Exchange Benchmark
    let iterations = 10_000;
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = diffie_hellman(&alice.private_key, &bob.public_key);
    }
    let elapsed = start.elapsed();
    let kex_per_sec = (iterations as f64) / elapsed.as_secs_f64();
    println!(" [X25519 ECDH]");
    println!("   Iterasjoner : {}", iterations);
    println!("   Total tid   : {:?}", elapsed);
    println!("   Hastighet   : {:.2} KEX ops/sek\n", kex_per_sec);

    // 2. HKDF-SHA256 Key Derivation Benchmark
    let secret = [0x42u8; KEY_LEN];
    let hash = [0x99u8; 32];
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = derive_session_keys(&secret, &hash).unwrap();
    }
    let elapsed = start.elapsed();
    let hkdf_per_sec = (iterations as f64) / elapsed.as_secs_f64();
    println!(" [HKDF-SHA256]");
    println!("   Iterasjoner : {}", iterations);
    println!("   Total tid   : {:?}", elapsed);
    println!("   Hastighet   : {:.2} avledninger/sek\n", hkdf_per_sec);

    // 3. ChaCha20-Poly1305 AEAD Throughput Benchmark
    let chunk_size = 16 * 1024; // 16 KB
    let payload = vec![0xABu8; chunk_size];
    let aead_iterations = 20_000;
    let mut cipher = CipherState::new([0x77u8; KEY_LEN]);

    let start = Instant::now();
    let mut total_bytes = 0usize;
    for _ in 0..aead_iterations {
        let ct = cipher.encrypt(&payload, b"aad-metadata").unwrap();
        total_bytes += ct.len();
    }
    let elapsed = start.elapsed();
    let mb_processed = (total_bytes as f64) / (1024.0 * 1024.0);
    let throughput = mb_processed / elapsed.as_secs_f64();
    println!(" [ChaCha20-Poly1305 AEAD 16KB Blokk]");
    println!("   Datamengde  : {:.2} MB", mb_processed);
    println!("   Total tid   : {:?}", elapsed);
    println!(
        "   Gjennomstrømming: {:.2} MB/s ({:.2} Gbps)\n",
        throughput,
        throughput * 0.008
    );

    // 4. Anti-Replay Sliding Window Filter Benchmark
    let mut filter = ReplayFilter::new();
    let filter_iterations = 100_000;
    let start = Instant::now();
    for i in 1..=filter_iterations {
        let _ = filter.validate_and_record(i);
    }
    let elapsed = start.elapsed();
    let filter_per_sec = (filter_iterations as f64) / elapsed.as_secs_f64();
    println!(" [Anti-Replay Sliding Window Filter]");
    println!("   Iterasjoner : {}", filter_iterations);
    println!("   Hastighet   : {:.2} ops/sek\n", filter_per_sec);

    // 5. Wire Framing Serialization Benchmark
    let frame = WireFrame::new(MessageType::DataPayload, 1, payload);
    let frame_iterations = 20_000;
    let start = Instant::now();
    for _ in 0..frame_iterations {
        let _ = frame.serialize();
    }
    let elapsed = start.elapsed();
    let frame_per_sec = (frame_iterations as f64) / elapsed.as_secs_f64();
    println!(" [Wire Framing Serialisering (Allokerende serialize)]");
    println!("   Iterasjoner : {}", frame_iterations);
    println!("   Hastighet   : {:.2} rammer/sek\n", frame_per_sec);

    // 6. Wire Framing Serialization with Buffer Reuse (serialize_into)
    let mut reused_buffer = Vec::with_capacity(16 * 1024 + 16);
    let start = Instant::now();
    for _ in 0..frame_iterations {
        reused_buffer.clear();
        frame.serialize_into(&mut reused_buffer);
    }
    let elapsed = start.elapsed();
    let reuse_per_sec = (frame_iterations as f64) / elapsed.as_secs_f64();
    println!(" [Wire Framing Serialisering (Gjenbruk serialize_into)]");
    println!("   Iterasjoner : {}", frame_iterations);
    println!("   Hastighet   : {:.2} rammer/sek\n", reuse_per_sec);

    println!("========================================================\n");
}
