/**
 * Cryptographic Test Vectors for Cross-Platform Compatibility
 *
 * Run with: cargo test generate_ -- --nocapture
 * This outputs test vectors that can be verified in TypeScript implementation
 */

#[cfg(test)]
mod crypto_test_vectors {
    use shared::encryption;
    use ring::signature::KeyPair;

    #[test]
    fn generate_sha256_test_vectors() {
        println!("\n========================================");
        println!("SHA-256 Test Vectors");
        println!("========================================\n");

        let test_cases = vec![
            (b"test".to_vec(), "Input: 'test'"),
            (b"hello world".to_vec(), "Input: 'hello world'"),
            (b"".to_vec(), "Input: '' (empty)"),
            (b"Cyfra2 secure messaging".to_vec(), "Input: 'Cyfra2 secure messaging'"),
            (b"The quick brown fox jumps over the lazy dog".to_vec(), "Input: 'The quick brown fox...'"),
        ];

        for (input, description) in test_cases {
            let hash = encryption::hash(&input);
            println!("{}", description);
            println!("SHA-256: {}\n", hex::encode(&hash));
        }
    }

    #[test]
    fn generate_user_key_derivation_vectors() {
        println!("\n========================================");
        println!("User Key Derivation Test Vectors");
        println!("========================================\n");

        let test_users = vec![
            ("alice", "password123"),
            ("bob", "secret456"),
            ("", ""),  // Edge case: empty
            ("test@example.com", "P@ssw0rd!"),
        ];

        for (username, password) in test_users {
            // This matches shared/src/users.rs::get_hashes()
            let mut combined = username.as_bytes().to_vec();
            combined.extend_from_slice(password.as_bytes());

            let key_hash = encryption::hash(&combined);
            let enc_hash = encryption::hash(password.as_bytes());

            println!("Username: {:?}", username);
            println!("Password: {:?}", password);
            println!("DB Key  (SHA256(username + password)): {}", hex::encode(&key_hash));
            println!("Enc Key (SHA256(password)):             {}\n", hex::encode(&enc_hash));
        }
    }

    #[test]
    fn generate_x25519_test_vectors() {
        use x25519_dalek::{StaticSecret, PublicKey};

        println!("\n========================================");
        println!("X25519 Key Exchange Test Vectors");
        println!("========================================\n");

        // Use fixed seeds for reproducibility
        let alice_seed = [1u8; 32];
        let bob_seed = [2u8; 32];

        let alice_secret = StaticSecret::from(alice_seed);
        let alice_public = PublicKey::from(&alice_secret);

        let bob_secret = StaticSecret::from(bob_seed);
        let bob_public = PublicKey::from(&bob_secret);

        // Compute shared secrets (should be identical)
        let alice_shared = alice_secret.diffie_hellman(&bob_public);
        let bob_shared = bob_secret.diffie_hellman(&alice_public);

        println!("Alice's Private Key: {}", hex::encode(alice_secret.to_bytes()));
        println!("Alice's Public Key:  {}", hex::encode(alice_public.as_bytes()));
        println!();
        println!("Bob's Private Key:   {}", hex::encode(bob_secret.to_bytes()));
        println!("Bob's Public Key:    {}", hex::encode(bob_public.as_bytes()));
        println!();
        println!("Alice's Shared Secret: {}", hex::encode(alice_shared.as_bytes()));
        println!("Bob's Shared Secret:   {}", hex::encode(bob_shared.as_bytes()));
        println!("Secrets Match: {}\n", alice_shared.as_bytes() == bob_shared.as_bytes());
    }

    #[test]
    fn generate_aes_gcm_test_vectors() {
        println!("\n========================================");
        println!("AES-256-GCM Test Vectors");
        println!("========================================\n");

        // Test with known key and plaintext
        let key = [0u8; 32]; // All zeros for reproducibility
        let plaintext_cases = vec![
            b"Hello from Rust!".to_vec(),
            b"Short".to_vec(),
            b"".to_vec(), // Empty
            b"This is a longer message to test AES-GCM encryption compatibility between Rust and TypeScript implementations.".to_vec(),
        ];

        for (i, plaintext) in plaintext_cases.iter().enumerate() {
            let encrypted = encryption::encrypt_data(&key, plaintext, b"").unwrap();

            println!("Test Case {}:", i + 1);
            println!("Key:         {}", hex::encode(&key));
            println!("Plaintext:   {:?}", String::from_utf8_lossy(plaintext));
            println!("AAD:         (empty)");
            println!("Encrypted:   {}", hex::encode(&encrypted));
            println!("Length:      {} bytes\n", encrypted.len());
        }
    }

    #[test]
    fn generate_aes_gcm_round_trip() {
        println!("\n========================================");
        println!("AES-256-GCM Round Trip Test");
        println!("========================================\n");

        let key = [42u8; 32]; // Different key
        let plaintext = b"Round trip test message";
        let aad = b"additional authenticated data";

        let encrypted = encryption::encrypt_data(&key, plaintext, aad).unwrap();
        let decrypted = encryption::decrypt_data(&key, &mut encrypted.clone(), aad).unwrap();

        println!("Key:       {}", hex::encode(&key));
        println!("Plaintext: {:?}", String::from_utf8_lossy(plaintext));
        println!("AAD:       {:?}", String::from_utf8_lossy(aad));
        println!("Encrypted: {}", hex::encode(&encrypted));
        println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
        println!("Match:     {}\n", plaintext == decrypted.as_slice());
    }

    #[test]
    fn generate_ed25519_test_vectors() {
        use ring::signature::Ed25519KeyPair;

        println!("\n========================================");
        println!("Ed25519 Signature Test Vectors");
        println!("========================================\n");

        // Generate keypair from PKCS8
        let pkcs8 = encryption::generate_pkcs8_bytes().unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let messages = vec![
            b"test message".to_vec(),
            b"nonce challenge".to_vec(),
        ];

        println!("Public Key: {}\n", hex::encode(keypair.public_key().as_ref()));

        for (i, message) in messages.iter().enumerate() {
            let signature = keypair.sign(message);

            println!("Message {}:   {:?}", i + 1, String::from_utf8_lossy(message));
            println!("Signature {}: {}\n", i + 1, hex::encode(signature.as_ref()));

            // Verify
            let verify_result = encryption::verify(message, keypair.public_key().as_ref(), signature.as_ref());
            println!("Verified:   {:?}\n", verify_result.is_ok());
        }
    }

    #[test]
    fn generate_message_encryption_flow_test() {
        use x25519_dalek::{StaticSecret, PublicKey};
        use serde::{Serialize, Deserialize};

        println!("\n========================================");
        println!("Message Encryption Flow Test Vector");
        println!("========================================\n");

        // Use same fixed keys as TypeScript test
        let alice_enc_priv = StaticSecret::from([1u8; 32]);
        let bob_enc_pub = PublicKey::from([
            0xce, 0x8d, 0x3a, 0xd1, 0xcc, 0xb6, 0x33, 0xec,
            0x7b, 0x70, 0xc1, 0x78, 0x14, 0xa5, 0xc7, 0x6e,
            0xcd, 0x02, 0x96, 0x85, 0x05, 0x0d, 0x34, 0x47,
            0x45, 0xba, 0x05, 0x87, 0x0e, 0x58, 0x7d, 0x59,
        ]);

        // Compute shared secret
        let shared_secret = alice_enc_priv.diffie_hellman(&bob_enc_pub);

        // Create message matching TypeScript structure
        #[derive(Serialize, Deserialize)]
        struct TestMessage {
            chat_id: u32,
            version: String,
            id: u32,
            time: u64,
            sender_name: String,
            sender_pub_key: String,
            recipient_name: String,
            recipient_pub_key: String,
            data: Vec<u8>,
            additional_data: Vec<u8>,
        }

        let message = TestMessage {
            chat_id: 12345,
            version: "2.0.0".to_string(),
            id: 67890,
            time: 1699999999,
            sender_name: "alice".to_string(),
            sender_pub_key: "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209".to_string(),
            recipient_name: "bob".to_string(),
            recipient_pub_key: "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59".to_string(),
            data: b"Hello from mobile!".to_vec(),
            additional_data: Vec::new(),
        };

        // Serialize to JSON
        let message_json = serde_json::to_string(&message).unwrap();

        // Encrypt with AES-256-GCM
        let encrypted = encryption::encrypt_data(
            shared_secret.as_bytes(),
            message_json.as_bytes(),
            b"",
        ).unwrap();

        println!("Alice Enc Private: {}", hex::encode(alice_enc_priv.to_bytes()));
        println!("Bob Enc Public:    {}", hex::encode(bob_enc_pub.as_bytes()));
        println!("Shared Secret:     {}", hex::encode(shared_secret.as_bytes()));
        println!("Message JSON:      {}", message_json);
        println!("Encrypted Length:  {}", encrypted.len());
        println!("Encrypted Hex:     {}", hex::encode(&encrypted));

        // Verify we can decrypt it back
        let decrypted = encryption::decrypt_data(
            shared_secret.as_bytes(),
            &mut encrypted.clone(),
            b"",
        ).unwrap();

        let decrypted_message: TestMessage = serde_json::from_slice(&decrypted).unwrap();
        let decrypted_text = String::from_utf8(decrypted_message.data).unwrap();

        println!("Decrypted Text:    {}", decrypted_text);
        println!("Match:             {}\n", decrypted_text == "Hello from mobile!");
    }
}
