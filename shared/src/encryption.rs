use ::rand::rngs::OsRng;
use x25519_dalek::StaticSecret;

use ring::{
    aead::{
        self, Aad, BoundKey, Nonce, NonceSequence, OpeningKey, UnboundKey, AES_256_GCM, NONCE_LEN,
    },
    digest::{digest, SHA256},
    rand,
    signature::{self, KeyPair, ED25519},
};

use serde::{Serialize, Deserialize};

pub type LongtermKeyPair = signature::Ed25519KeyPair;

// Encryption Keys
pub type EncPrivKey = x25519_dalek::StaticSecret;
pub type EncPubKey = x25519_dalek::PublicKey;
pub type UnspecifiedError = ring::error::Unspecified;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableKeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}


pub fn generate_enc_keypair() -> (EncPrivKey, EncPubKey) {
    // Generate an ephemeral private key

    let private_key = StaticSecret::random_from_rng(OsRng);

    // Compute the public key
    let public_key = x25519_dalek::PublicKey::from(&private_key);

    // let private_key_bytes: [u8; 8] = private_key.into();

    (private_key, public_key)
}

pub fn generate_pkcs8_bytes() -> Result<Vec<u8>, UnspecifiedError> {
    let rng = rand::SystemRandom::new();
    let pkcs8 = LongtermKeyPair::generate_pkcs8(&rng)?;

    Ok(pkcs8.as_ref().to_vec())
}

pub fn generate_longterm_keypair(pkcs8: &[u8]) -> Result<LongtermKeyPair, UnspecifiedError> {

    match LongtermKeyPair::from_pkcs8(pkcs8.as_ref()) {
        Ok(val) => Ok(val),
        Err(_) => Err(ring::error::Unspecified),
    }
}

pub fn get_public_key_from_longterm_keypair(key_pair: &LongtermKeyPair) -> &[u8] {
    key_pair.public_key().as_ref()
}

pub fn sign(message: &[u8], key_pair: &LongtermKeyPair) -> Vec<u8> {
    key_pair.sign(&message).as_ref().to_vec()
}

pub fn verify(message: &[u8], pubkey: &[u8], signature: &[u8]) -> Result<(), UnspecifiedError> {
    let peer_pubkey = signature::UnparsedPublicKey::new(&ED25519, &pubkey);
    peer_pubkey.verify(&message, &signature)
}

pub fn get_shared_secret(
    pubkey: &[u8; 32],
    my_private_key: &[u8; 32],
) -> Result<Vec<u8>, UnspecifiedError> {


    let peer_pubkey = EncPubKey::from(*pubkey);
    let my_privkey = EncPrivKey::from(*my_private_key);

    let shared_secret = my_privkey.diffie_hellman(&peer_pubkey);

    Ok(shared_secret.to_bytes().to_vec())

}

struct CounterNonceSequence(u32);

impl NonceSequence for CounterNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        let mut nonce_bytes = vec![0; NONCE_LEN];
        let bytes = self.0.to_be_bytes();
        nonce_bytes[8..].copy_from_slice(&bytes);

        self.0 += 1;
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

pub fn encrypt_data(key: &[u8], data: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, UnspecifiedError> {

    let aead_alg = &AES_256_GCM;
    let nonce_sequence = CounterNonceSequence(1);
    let unbound_key = aead::UnboundKey::new(&aead_alg, key)?;
    let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_sequence);
    let associated_data = Aad::from(associated_data);
    let mut data_vec = data.to_owned();
    sealing_key.seal_in_place_append_tag(associated_data, &mut data_vec)?;

    Ok(data_vec)
}

pub fn decrypt_data(
    key: &[u8],
    encrypted_data: &mut [u8],
    associated_data: &[u8]) -> Result<Vec<u8>, UnspecifiedError> {


    let aead_alg = &AES_256_GCM;
    let nonce_sequence = CounterNonceSequence(1);
    let unbound_key = UnboundKey::new(&aead_alg, key)?;
    let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);
    let associated_data = Aad::from(associated_data);
    let decrypted_data = opening_key.open_in_place(associated_data, encrypted_data)?;

    Ok(decrypted_data.to_owned())
}


//User cred hashing
pub fn hash(raw_data: &[u8]) -> Vec<u8> {
    let sha256_digest = digest(&SHA256, raw_data);
    sha256_digest.as_ref().to_owned()
}


#[cfg(test)]
mod tests {
    use crate::encryption::{decrypt_data, encrypt_data, get_public_key_from_longterm_keypair};

    use super::{generate_pkcs8_bytes, generate_enc_keypair, generate_longterm_keypair, get_shared_secret, sign, verify};



    #[test]
    fn check_sign_and_verify() {
        let message: Vec<u8> = "HOLA THIS IS WRITTEN BY ME".as_bytes().to_vec();
        let pkcs8 = generate_pkcs8_bytes().unwrap();
        let longterm_keypair = generate_longterm_keypair(&pkcs8).unwrap();

        let signature = sign(&message, &longterm_keypair);

        let pubkey = get_public_key_from_longterm_keypair(&longterm_keypair);

        assert_eq!(verify(&message, pubkey, &signature), Ok(()));

    }

    #[test]
    fn encrypt_and_decrypt_data() {

        let (alice_priv, alice_pub) = generate_enc_keypair();
        let (bob_priv, bob_pub) = generate_enc_keypair();

        let alice_priv: [u8; 32] = alice_priv.to_bytes().try_into().expect("Key gen error");
        let bob_priv: [u8; 32] = bob_priv.to_bytes().try_into().expect("Key gen error");

        let alice_pub: [u8; 32] = alice_pub.to_bytes().try_into().expect("Key gen error");
        let bob_pub: [u8; 32] = bob_pub.to_bytes().try_into().expect("Key gen error");

        let shared_secret_alice = get_shared_secret(&bob_pub, &alice_priv).unwrap();
        let shared_secret_bob = get_shared_secret(&alice_pub, &bob_priv).unwrap();

        //Make sure both secrets are the same
        assert_eq!(shared_secret_bob, shared_secret_alice);

        let message = "CAN YOU READ this???".as_bytes().to_vec();



        let mut encrypted_data = encrypt_data(shared_secret_bob.as_ref(), message.as_ref(), "empty".as_ref()).unwrap();

        let decrypted_message = decrypt_data(shared_secret_alice.as_ref(), &mut encrypted_data, "empty".as_ref()).unwrap();

        assert_eq!(message, decrypted_message);


    }

    #[test]
    fn test_gen() {
        generate_enc_keypair();
    }
}
