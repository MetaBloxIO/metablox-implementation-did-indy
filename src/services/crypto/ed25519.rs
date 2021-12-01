use indy_api_types::errors::IndyError;
use super::CryptoType;
use indy_utils::crypto::ed25519_box;
use indy_utils::crypto::ed25519_sign;
use indy_utils::crypto::sealedbox;

pub struct ED25519CryptoType {}

impl ED25519CryptoType {
    pub fn new() -> ED25519CryptoType {
        ED25519CryptoType {}
    }
}

impl CryptoType for ED25519CryptoType {
    fn crypto_box(&self, sk: &ed25519_sign::SecretKey, vk: &ed25519_sign::PublicKey, doc: &[u8], nonce: &ed25519_box::Nonce) -> Result<Vec<u8>, IndyError> {
        ed25519_box::encrypt(&ed25519_sign::sk_to_curve25519(sk)?,
                           &ed25519_sign::vk_to_curve25519(vk)?, doc, nonce)
    }

    fn crypto_box_open(&self, sk: &ed25519_sign::SecretKey, vk: &ed25519_sign::PublicKey, doc: &[u8], nonce: &ed25519_box::Nonce) -> Result<Vec<u8>, IndyError> {
        ed25519_box::decrypt(&ed25519_sign::sk_to_curve25519(sk)?,
                           &ed25519_sign::vk_to_curve25519(vk)?, doc, nonce)
    }

    fn gen_nonce(&self) -> ed25519_box::Nonce {
        ed25519_box::gen_nonce()
    }

    fn create_key(&self, seed: Option<&[u8; 32]>) -> Result<(secp256k1::PublicKey, secp256k1::SecretKey), IndyError> {
        ed25519_sign::create_key_pair_for_signature(seed)
    }

    fn sign(&self, sk: &secp256k1::SecretKey, doc: &[u8]) -> Result<secp256k1::Signature, IndyError> {
        ed25519_sign::sign(sk, doc)
    }

    fn verify(&self, vk: &secp256k1::PublicKey, doc: &[u8], signature: &secp256k1::Signature) -> Result<bool, IndyError> {
        ed25519_sign::verify(vk, doc, signature)
    }

    fn crypto_box_seal(&self, vk: &ed25519_sign::PublicKey, doc: &[u8]) -> Result<Vec<u8>, IndyError> {
        sealedbox::encrypt(&ed25519_sign::vk_to_curve25519(vk)?, doc)
    }

    fn crypto_box_seal_open(&self, vk: &ed25519_sign::PublicKey, sk: &ed25519_sign::SecretKey, doc: &[u8]) -> Result<Vec<u8>, IndyError> {
        sealedbox::decrypt(&ed25519_sign::vk_to_curve25519(vk)?,
                         &ed25519_sign::sk_to_curve25519(sk)?, doc)
    }

    fn validate_key(&self, _vk: &ed25519_sign::PublicKey) -> Result<(), IndyError> {
        // TODO: FIXME: Validate key
        Ok(())
    }
}